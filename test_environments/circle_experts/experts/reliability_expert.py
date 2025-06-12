"""
Reliability Expert - Specialized in system reliability and fault tolerance
Failure scenario testing, recovery optimization, and stability analysis
"""

import asyncio
import logging
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import statistics


class FailureMode(Enum):
    HARDWARE_FAILURE = "hardware_failure"
    SOFTWARE_CRASH = "software_crash"
    NETWORK_PARTITION = "network_partition"
    DATABASE_FAILURE = "database_failure"
    SERVICE_TIMEOUT = "service_timeout"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    CASCADING_FAILURE = "cascading_failure"


class RecoveryStrategy(Enum):
    IMMEDIATE_RESTART = "immediate_restart"
    GRACEFUL_RESTART = "graceful_restart"
    FAILOVER = "failover"
    CIRCUIT_BREAKER = "circuit_breaker"
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    DEGRADED_SERVICE = "degraded_service"


@dataclass
class ReliabilityAnalysis:
    """Reliability analysis result"""
    failure_scenarios: List[str]
    recovery_mechanisms: List[str]
    reliability_score: float
    mtbf_estimate: float  # Mean Time Between Failures (hours)
    mttr_estimate: float  # Mean Time To Recovery (minutes)
    critical_dependencies: List[str]
    risk_factors: List[str]
    resilience_gaps: List[str]


class ReliabilityExpert:
    """
    Expert specializing in system reliability and fault tolerance
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.name = "Reliability Expert"
        self.specializations = [
            "failure_analysis",
            "recovery_strategies",
            "fault_tolerance",
            "chaos_engineering",
            "disaster_recovery",
            "stability_testing"
        ]
        
        # Reliability targets
        self.targets = {
            'uptime': 0.999,  # 99.9% uptime
            'mtbf_hours': 720,  # 30 days
            'mttr_minutes': 5,  # 5 minutes recovery
            'error_rate': 0.001,  # 0.1% error rate
            'availability': 0.99  # 99% availability
        }
        
        # Failure patterns database
        self.failure_patterns: Dict[str, List[str]] = {
            'high_load': ['service_timeout', 'resource_exhaustion', 'cascading_failure'],
            'network_issues': ['network_partition', 'service_timeout', 'database_failure'],
            'resource_pressure': ['memory_exhaustion', 'cpu_starvation', 'disk_full'],
            'dependency_failure': ['database_failure', 'external_service_down', 'cascading_failure']
        }
        
        # Recovery patterns
        self.recovery_patterns: Dict[str, RecoveryStrategy] = {
            'service_timeout': RecoveryStrategy.RETRY_WITH_BACKOFF,
            'resource_exhaustion': RecoveryStrategy.GRACEFUL_RESTART,
            'network_partition': RecoveryStrategy.DEGRADED_SERVICE,
            'database_failure': RecoveryStrategy.FAILOVER,
            'software_crash': RecoveryStrategy.IMMEDIATE_RESTART,
            'cascading_failure': RecoveryStrategy.CIRCUIT_BREAKER
        }
        
        # Historical reliability data
        self.reliability_history: List[Dict[str, Any]] = []
        
    async def analyze_and_recommend(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze system reliability and provide expert recommendations
        """
        self.logger.info("Reliability Expert analyzing system reliability")
        
        try:
            # Extract reliability metrics
            current_metrics = context.get('current_metrics', {})
            system_state = context.get('system_state', {})
            historical_data = context.get('historical_data', [])
            objectives = context.get('objectives', [])
            
            # Perform comprehensive reliability analysis
            analysis = await self._analyze_reliability(
                current_metrics, system_state, historical_data
            )
            
            # Generate reliability strategy
            strategy = await self._generate_reliability_strategy(analysis, objectives)
            
            # Assess confidence based on data patterns and history
            confidence = self._calculate_confidence(current_metrics, historical_data)
            
            # Generate implementation steps
            implementation_steps = self._generate_implementation_steps(strategy, analysis)
            
            # Identify metrics to monitor
            metrics_to_monitor = self._identify_monitoring_metrics(analysis)
            
            recommendation = {
                'strategy': strategy['name'],
                'confidence': confidence,
                'reasoning': self._generate_reasoning(analysis, strategy),
                'expected_outcome': strategy['expected_outcome'],
                'risk_assessment': self._assess_overall_risk(analysis),
                'implementation_steps': implementation_steps,
                'metrics_to_monitor': metrics_to_monitor,
                'reliability_analysis': {
                    'failure_scenarios': analysis.failure_scenarios,
                    'recovery_mechanisms': analysis.recovery_mechanisms,
                    'reliability_score': analysis.reliability_score,
                    'mtbf_estimate': analysis.mtbf_estimate,
                    'mttr_estimate': analysis.mttr_estimate,
                    'critical_dependencies': analysis.critical_dependencies,
                    'resilience_gaps': analysis.resilience_gaps
                }
            }
            
            # Store analysis for learning
            self._store_analysis(analysis, recommendation)
            
            return recommendation
            
        except Exception as e:
            self.logger.error(f"Reliability analysis failed: {str(e)}")
            return self._generate_fallback_recommendation()
    
    async def _analyze_reliability(
        self,
        current_metrics: Dict[str, Any],
        system_state: Dict[str, Any],
        historical_data: List[Dict[str, Any]]
    ) -> ReliabilityAnalysis:
        """Comprehensive reliability analysis"""
        
        # Identify potential failure scenarios
        failure_scenarios = await self._identify_failure_scenarios(current_metrics, system_state)
        
        # Analyze recovery mechanisms
        recovery_mechanisms = await self._analyze_recovery_mechanisms(system_state)
        
        # Calculate reliability score
        reliability_score = self._calculate_reliability_score(current_metrics, historical_data)
        
        # Estimate MTBF and MTTR
        mtbf_estimate = self._estimate_mtbf(historical_data)
        mttr_estimate = self._estimate_mttr(historical_data)
        
        # Identify critical dependencies
        critical_dependencies = self._identify_critical_dependencies(system_state)
        
        # Assess risk factors
        risk_factors = await self._assess_risk_factors(current_metrics, system_state)
        
        # Identify resilience gaps
        resilience_gaps = await self._identify_resilience_gaps(
            failure_scenarios, recovery_mechanisms, system_state
        )
        
        return ReliabilityAnalysis(
            failure_scenarios=failure_scenarios,
            recovery_mechanisms=recovery_mechanisms,
            reliability_score=reliability_score,
            mtbf_estimate=mtbf_estimate,
            mttr_estimate=mttr_estimate,
            critical_dependencies=critical_dependencies,
            risk_factors=risk_factors,
            resilience_gaps=resilience_gaps
        )
    
    async def _identify_failure_scenarios(
        self,
        current_metrics: Dict[str, Any],
        system_state: Dict[str, Any]
    ) -> List[str]:
        """Identify potential failure scenarios"""
        scenarios = []
        
        # High load scenarios
        cpu_usage = current_metrics.get('cpu_utilization', 0)
        memory_usage = current_metrics.get('memory_usage', 0)
        if cpu_usage > 80 or memory_usage > 85:
            scenarios.extend([
                "Resource exhaustion under sustained high load",
                "Service degradation due to resource pressure",
                "Potential cascading failures from resource contention"
            ])
        
        # Network-related scenarios
        error_rate = current_metrics.get('error_rate', 0)
        response_time = current_metrics.get('response_time', 0)
        if error_rate > 0.05 or response_time > 1000:
            scenarios.extend([
                "Network partition causing service isolation",
                "Timeout failures in distributed communications",
                "Service mesh instability affecting reliability"
            ])
        
        # Database scenarios
        db_connections = system_state.get('database_connections', 0)
        max_db_connections = system_state.get('max_database_connections', 100)
        if db_connections > max_db_connections * 0.8:
            scenarios.extend([
                "Database connection pool exhaustion",
                "Database deadlock scenarios",
                "Database failover requirement"
            ])
        
        # Dependency scenarios
        external_dependencies = system_state.get('external_dependencies', [])
        if len(external_dependencies) > 3:
            scenarios.extend([
                "External service dependency failure",
                "Third-party API rate limiting",
                "Upstream service cascade failure"
            ])
        
        # Memory scenarios
        if memory_usage > 90:
            scenarios.extend([
                "Memory leak leading to OOM conditions",
                "Garbage collection pressure affecting performance",
                "Memory fragmentation causing allocation failures"
            ])
        
        # Concurrency scenarios
        concurrent_requests = current_metrics.get('concurrent_requests', 0)
        max_capacity = current_metrics.get('max_capacity', 1000)
        if concurrent_requests > max_capacity * 0.9:
            scenarios.extend([
                "Thread pool exhaustion under load",
                "Deadlock conditions in concurrent processing",
                "Race conditions causing data inconsistency"
            ])
        
        return scenarios
    
    async def _analyze_recovery_mechanisms(self, system_state: Dict[str, Any]) -> List[str]:
        """Analyze existing recovery mechanisms"""
        mechanisms = []
        
        # Check for circuit breakers
        if system_state.get('circuit_breakers_enabled', False):
            mechanisms.append("Circuit breaker protection for external calls")
        else:
            mechanisms.append("Missing: Circuit breaker implementation needed")
        
        # Check for retry logic
        if system_state.get('retry_mechanisms', False):
            mechanisms.append("Retry logic with exponential backoff")
        else:
            mechanisms.append("Missing: Retry mechanism implementation needed")
        
        # Check for health checks
        if system_state.get('health_checks', False):
            mechanisms.append("Health check endpoints for monitoring")
        else:
            mechanisms.append("Missing: Health check implementation needed")
        
        # Check for graceful shutdown
        if system_state.get('graceful_shutdown', False):
            mechanisms.append("Graceful shutdown handling")
        else:
            mechanisms.append("Missing: Graceful shutdown implementation needed")
        
        # Check for failover capabilities
        if system_state.get('failover_enabled', False):
            mechanisms.append("Automatic failover to backup systems")
        else:
            mechanisms.append("Missing: Failover mechanism needed")
        
        # Check for data backup
        if system_state.get('backup_strategy', False):
            mechanisms.append("Data backup and recovery procedures")
        else:
            mechanisms.append("Missing: Backup strategy implementation needed")
        
        # Check for monitoring
        if system_state.get('monitoring_enabled', False):
            mechanisms.append("Comprehensive monitoring and alerting")
        else:
            mechanisms.append("Missing: Monitoring system implementation needed")
        
        return mechanisms
    
    def _calculate_reliability_score(
        self,
        current_metrics: Dict[str, Any],
        historical_data: List[Dict[str, Any]]
    ) -> float:
        """Calculate overall reliability score (0-1)"""
        scores = []
        
        # Uptime score
        uptime = current_metrics.get('uptime', 0.99)
        uptime_score = min(1.0, uptime / self.targets['uptime'])
        scores.append(uptime_score * 0.3)  # 30% weight
        
        # Error rate score (inverted - lower is better)
        error_rate = current_metrics.get('error_rate', 0.01)
        error_score = max(0, min(1, (self.targets['error_rate'] - error_rate) / self.targets['error_rate']))
        scores.append(error_score * 0.25)  # 25% weight
        
        # Availability score
        availability = current_metrics.get('availability', 0.95)
        availability_score = min(1.0, availability / self.targets['availability'])
        scores.append(availability_score * 0.25)  # 25% weight
        
        # Historical stability score
        if len(historical_data) >= 5:
            # Check for stability trends
            recent_uptimes = [d.get('uptime', 0.99) for d in historical_data[-5:]]
            stability = 1.0 - statistics.stdev(recent_uptimes) if len(set(recent_uptimes)) > 1 else 1.0
            scores.append(stability * 0.1)  # 10% weight
        else:
            scores.append(0.8 * 0.1)  # Default stability score
        
        # Recovery capability score
        recovery_time = current_metrics.get('average_recovery_time', 10)  # minutes
        recovery_score = max(0, min(1, (self.targets['mttr_minutes'] - recovery_time) / self.targets['mttr_minutes']))
        scores.append(recovery_score * 0.1)  # 10% weight
        
        return sum(scores)
    
    def _estimate_mtbf(self, historical_data: List[Dict[str, Any]]) -> float:
        """Estimate Mean Time Between Failures"""
        if len(historical_data) < 3:
            return self.targets['mtbf_hours'] * 0.8  # Conservative estimate
        
        # Count failures in historical data
        failures = sum(1 for d in historical_data if d.get('failure_occurred', False))
        if failures == 0:
            return self.targets['mtbf_hours'] * 1.2  # Better than target
        
        # Calculate time period
        time_period_hours = len(historical_data) * 1  # Assuming 1 hour intervals
        
        # MTBF = Total time / Number of failures
        mtbf = time_period_hours / failures
        
        return max(24, min(8760, mtbf))  # Between 1 day and 1 year
    
    def _estimate_mttr(self, historical_data: List[Dict[str, Any]]) -> float:
        """Estimate Mean Time To Recovery"""
        if len(historical_data) < 3:
            return self.targets['mttr_minutes'] * 1.5  # Conservative estimate
        
        # Extract recovery times from historical data
        recovery_times = [d.get('recovery_time_minutes', 5) for d in historical_data if d.get('failure_occurred', False)]
        
        if not recovery_times:
            return self.targets['mttr_minutes']  # Target value if no failures
        
        # Calculate average recovery time
        avg_recovery_time = statistics.mean(recovery_times)
        
        return max(1, min(60, avg_recovery_time))  # Between 1 minute and 1 hour
    
    def _identify_critical_dependencies(self, system_state: Dict[str, Any]) -> List[str]:
        """Identify critical system dependencies"""
        dependencies = []
        
        # Database dependencies
        if system_state.get('database_enabled', True):
            dependencies.append("Primary database system")
        
        # External service dependencies
        external_services = system_state.get('external_dependencies', [])
        for service in external_services:
            dependencies.append(f"External service: {service}")
        
        # Infrastructure dependencies
        if system_state.get('load_balancer', False):
            dependencies.append("Load balancer infrastructure")
        
        if system_state.get('message_queue', False):
            dependencies.append("Message queue system")
        
        if system_state.get('cache_system', False):
            dependencies.append("Caching layer")
        
        if system_state.get('monitoring_system', False):
            dependencies.append("Monitoring and alerting system")
        
        # Network dependencies
        dependencies.append("Network connectivity and DNS resolution")
        dependencies.append("SSL/TLS certificate validity")
        
        return dependencies
    
    async def _assess_risk_factors(
        self,
        current_metrics: Dict[str, Any],
        system_state: Dict[str, Any]
    ) -> List[str]:
        """Assess reliability risk factors"""
        risk_factors = []
        
        # High resource utilization risks
        cpu_usage = current_metrics.get('cpu_utilization', 0)
        memory_usage = current_metrics.get('memory_usage', 0)
        if cpu_usage > 80:
            risk_factors.append(f"High CPU utilization ({cpu_usage}%) increasing failure risk")
        if memory_usage > 85:
            risk_factors.append(f"High memory usage ({memory_usage}%) risking OOM conditions")
        
        # Performance degradation risks
        response_time = current_metrics.get('response_time', 0)
        if response_time > 500:
            risk_factors.append(f"Elevated response times ({response_time}ms) indicating stress")
        
        # Error rate risks
        error_rate = current_metrics.get('error_rate', 0)
        if error_rate > 0.01:
            risk_factors.append(f"Elevated error rate ({error_rate:.2%}) indicating instability")
        
        # Dependency risks
        external_dependencies = system_state.get('external_dependencies', [])
        if len(external_dependencies) > 5:
            risk_factors.append("High number of external dependencies increases failure surface")
        
        # Single point of failure risks
        if not system_state.get('redundancy_enabled', False):
            risk_factors.append("Lack of redundancy creates single points of failure")
        
        # Monitoring risks
        if not system_state.get('monitoring_enabled', False):
            risk_factors.append("Insufficient monitoring delays failure detection")
        
        # Backup risks
        if not system_state.get('backup_strategy', False):
            risk_factors.append("No backup strategy increases data loss risk")
        
        # Update and patching risks
        last_update = system_state.get('last_security_update_days', 30)
        if last_update > 30:
            risk_factors.append(f"Security updates delayed ({last_update} days) increasing vulnerability")
        
        return risk_factors
    
    async def _identify_resilience_gaps(
        self,
        failure_scenarios: List[str],
        recovery_mechanisms: List[str],
        system_state: Dict[str, Any]
    ) -> List[str]:
        """Identify gaps in system resilience"""
        gaps = []
        
        # Check for missing recovery mechanisms
        missing_mechanisms = [mech for mech in recovery_mechanisms if "Missing:" in mech]
        gaps.extend(missing_mechanisms)
        
        # Scenario-specific gaps
        for scenario in failure_scenarios:
            if "Resource exhaustion" in scenario:
                if not system_state.get('auto_scaling', False):
                    gaps.append("Auto-scaling not configured for resource exhaustion scenarios")
            
            if "Network partition" in scenario:
                if not system_state.get('circuit_breakers_enabled', False):
                    gaps.append("Circuit breakers needed for network partition resilience")
            
            if "Database" in scenario:
                if not system_state.get('database_replication', False):
                    gaps.append("Database replication needed for database failure scenarios")
            
            if "Cascading" in scenario:
                if not system_state.get('bulkhead_pattern', False):
                    gaps.append("Bulkhead pattern needed to prevent cascading failures")
        
        # Infrastructure gaps
        if not system_state.get('disaster_recovery_plan', False):
            gaps.append("Disaster recovery plan not implemented")
        
        if not system_state.get('chaos_engineering', False):
            gaps.append("Chaos engineering testing not implemented")
        
        if not system_state.get('incident_response_plan', False):
            gaps.append("Incident response procedures not documented")
        
        return gaps
    
    async def _generate_reliability_strategy(
        self,
        analysis: ReliabilityAnalysis,
        objectives: List[str]
    ) -> Dict[str, Any]:
        """Generate reliability improvement strategy"""
        
        # Determine strategy based on analysis
        if analysis.reliability_score < 0.5:
            strategy_name = "critical_reliability_overhaul"
            priority = "critical"
        elif analysis.reliability_score < 0.7:
            strategy_name = "comprehensive_reliability_improvement"
            priority = "high"
        elif analysis.reliability_score < 0.85:
            strategy_name = "targeted_reliability_enhancement"
            priority = "medium"
        else:
            strategy_name = "reliability_fine_tuning"
            priority = "low"
        
        # Define strategy details
        strategy = {
            'name': strategy_name,
            'priority': priority,
            'focus_areas': self._determine_focus_areas(analysis),
            'reliability_techniques': self._select_reliability_techniques(analysis),
            'expected_outcome': {
                'reliability_improvement': self._estimate_reliability_improvement(analysis),
                'mtbf_improvement': self._estimate_mtbf_improvement(analysis),
                'mttr_improvement': self._estimate_mttr_improvement(analysis),
                'success_probability': self._estimate_success_probability(analysis),
                'implementation_time': self._estimate_implementation_time(analysis),
                'risk_reduction': self._estimate_risk_reduction(analysis)
            },
            'testing_strategy': {
                'chaos_engineering': len(analysis.failure_scenarios) > 3,
                'disaster_recovery_drills': analysis.reliability_score < 0.8,
                'load_testing': True,
                'failure_injection': len(analysis.resilience_gaps) > 2
            }
        }
        
        return strategy
    
    def _determine_focus_areas(self, analysis: ReliabilityAnalysis) -> List[str]:
        """Determine reliability focus areas"""
        focus_areas = []
        
        # Based on reliability score
        if analysis.reliability_score < 0.7:
            focus_areas.append("fundamental_reliability")
        
        # Based on gaps
        if len(analysis.resilience_gaps) > 3:
            focus_areas.append("resilience_engineering")
        
        # Based on MTTR
        if analysis.mttr_estimate > self.targets['mttr_minutes'] * 2:
            focus_areas.append("recovery_optimization")
        
        # Based on MTBF
        if analysis.mtbf_estimate < self.targets['mtbf_hours'] * 0.5:
            focus_areas.append("failure_prevention")
        
        # Based on risk factors
        if len(analysis.risk_factors) > 4:
            focus_areas.append("risk_mitigation")
        
        # Based on dependencies
        if len(analysis.critical_dependencies) > 5:
            focus_areas.append("dependency_management")
        
        return focus_areas or ["general_reliability"]
    
    def _select_reliability_techniques(self, analysis: ReliabilityAnalysis) -> List[str]:
        """Select appropriate reliability techniques"""
        techniques = []
        
        # Based on gaps
        for gap in analysis.resilience_gaps:
            if "Circuit breaker" in gap:
                techniques.append("circuit_breaker_implementation")
            elif "Auto-scaling" in gap:
                techniques.append("auto_scaling_configuration")
            elif "Backup" in gap:
                techniques.append("backup_strategy_implementation")
            elif "Monitoring" in gap:
                techniques.append("monitoring_enhancement")
            elif "Health check" in gap:
                techniques.append("health_check_implementation")
        
        # Based on failure scenarios
        for scenario in analysis.failure_scenarios:
            if "Resource exhaustion" in scenario:
                techniques.append("resource_management_optimization")
            elif "Network" in scenario:
                techniques.append("network_resilience_patterns")
            elif "Database" in scenario:
                techniques.append("database_reliability_patterns")
            elif "Cascading" in scenario:
                techniques.append("bulkhead_pattern_implementation")
        
        # General techniques based on score
        if analysis.reliability_score < 0.8:
            techniques.extend([
                "comprehensive_testing_strategy",
                "incident_response_procedures",
                "monitoring_and_alerting"
            ])
        
        return list(set(techniques))[:8]  # Limit and remove duplicates
    
    def _estimate_reliability_improvement(self, analysis: ReliabilityAnalysis) -> float:
        """Estimate expected reliability improvement"""
        current_score = analysis.reliability_score
        gap_count = len(analysis.resilience_gaps)
        
        # Base improvement estimation
        if current_score < 0.5:
            base_improvement = 0.3  # Up to 30% improvement
        elif current_score < 0.7:
            base_improvement = 0.2  # Up to 20% improvement
        elif current_score < 0.85:
            base_improvement = 0.1  # Up to 10% improvement
        else:
            base_improvement = 0.05  # Up to 5% improvement
        
        # Adjust based on gaps
        gap_factor = min(1.0, gap_count * 0.05)
        estimated_improvement = base_improvement * (1 + gap_factor)
        
        return min(0.4, estimated_improvement)  # Cap at 40% improvement
    
    def _estimate_mtbf_improvement(self, analysis: ReliabilityAnalysis) -> float:
        """Estimate MTBF improvement ratio"""
        current_mtbf = analysis.mtbf_estimate
        target_mtbf = self.targets['mtbf_hours']
        
        if current_mtbf >= target_mtbf:
            return 1.1  # 10% improvement
        else:
            # Proportional improvement toward target
            improvement_ratio = min(2.0, target_mtbf / current_mtbf)
            return improvement_ratio
    
    def _estimate_mttr_improvement(self, analysis: ReliabilityAnalysis) -> float:
        """Estimate MTTR improvement ratio"""
        current_mttr = analysis.mttr_estimate
        target_mttr = self.targets['mttr_minutes']
        
        if current_mttr <= target_mttr:
            return 0.9  # 10% improvement
        else:
            # Proportional improvement toward target
            improvement_ratio = max(0.5, target_mttr / current_mttr)
            return improvement_ratio
    
    def _estimate_success_probability(self, analysis: ReliabilityAnalysis) -> float:
        """Estimate probability of successful reliability improvement"""
        base_probability = 0.8
        
        # Reduce probability based on complexity
        if len(analysis.resilience_gaps) > 5:
            base_probability *= 0.8
        elif len(analysis.resilience_gaps) > 3:
            base_probability *= 0.9
        
        # Adjust based on current reliability
        if analysis.reliability_score < 0.5:
            base_probability *= 0.7  # More complex improvements
        elif analysis.reliability_score < 0.7:
            base_probability *= 0.85
        
        return max(0.6, base_probability)  # Minimum 60% probability
    
    def _estimate_implementation_time(self, analysis: ReliabilityAnalysis) -> int:
        """Estimate implementation time in hours"""
        base_time = 16  # 16 hours base
        
        # Add time based on gaps
        gap_time = len(analysis.resilience_gaps) * 8
        
        # Add time based on complexity
        if analysis.reliability_score < 0.5:
            complexity_time = 40  # Major overhaul
        elif analysis.reliability_score < 0.7:
            complexity_time = 24  # Significant improvements
        else:
            complexity_time = 8   # Minor improvements
        
        total_time = base_time + gap_time + complexity_time
        
        return min(120, total_time)  # Cap at 120 hours
    
    def _estimate_risk_reduction(self, analysis: ReliabilityAnalysis) -> float:
        """Estimate risk reduction percentage"""
        risk_count = len(analysis.risk_factors)
        gap_count = len(analysis.resilience_gaps)
        
        # Base risk reduction
        base_reduction = 0.3  # 30% base reduction
        
        # Additional reduction based on improvements
        risk_reduction = base_reduction + (risk_count * 0.05) + (gap_count * 0.03)
        
        return min(0.7, risk_reduction)  # Cap at 70% risk reduction
    
    def _assess_overall_risk(self, analysis: ReliabilityAnalysis) -> str:
        """Assess overall reliability risk level"""
        risk_score = 0
        
        # Score based on reliability
        if analysis.reliability_score < 0.5:
            risk_score += 3
        elif analysis.reliability_score < 0.7:
            risk_score += 2
        elif analysis.reliability_score < 0.85:
            risk_score += 1
        
        # Score based on gaps
        risk_score += min(3, len(analysis.resilience_gaps) // 2)
        
        # Score based on MTTR
        if analysis.mttr_estimate > self.targets['mttr_minutes'] * 3:
            risk_score += 2
        elif analysis.mttr_estimate > self.targets['mttr_minutes'] * 2:
            risk_score += 1
        
        # Score based on risk factors
        risk_score += min(2, len(analysis.risk_factors) // 3)
        
        if risk_score >= 6:
            return "critical"
        elif risk_score >= 4:
            return "high"
        elif risk_score >= 2:
            return "medium"
        else:
            return "low"
    
    def _calculate_confidence(
        self,
        current_metrics: Dict[str, Any],
        historical_data: List[Dict[str, Any]]
    ) -> float:
        """Calculate confidence in the recommendation"""
        base_confidence = 0.75
        
        # Increase confidence with more historical data
        if len(historical_data) >= 10:
            base_confidence += 0.1
        elif len(historical_data) >= 5:
            base_confidence += 0.05
        
        # Increase confidence with more complete metrics
        key_metrics = ['uptime', 'error_rate', 'availability', 'response_time']
        metrics_coverage = sum(1 for metric in key_metrics if metric in current_metrics) / len(key_metrics)
        base_confidence += (metrics_coverage - 0.5) * 0.15
        
        return min(0.95, max(0.5, base_confidence))
    
    def _generate_reasoning(
        self,
        analysis: ReliabilityAnalysis,
        strategy: Dict[str, Any]
    ) -> str:
        """Generate reasoning for the recommendation"""
        reasoning_parts = []
        
        # Analysis summary
        reasoning_parts.append(f"Reliability analysis shows {analysis.reliability_score:.2f} current score")
        reasoning_parts.append(f"Identified {len(analysis.resilience_gaps)} resilience gaps")
        reasoning_parts.append(f"MTBF estimated at {analysis.mtbf_estimate:.1f} hours")
        reasoning_parts.append(f"MTTR estimated at {analysis.mttr_estimate:.1f} minutes")
        
        # Strategy justification
        reasoning_parts.append(f"Recommended {strategy['name']} approach")
        reasoning_parts.append(f"Expected {strategy['expected_outcome']['reliability_improvement']:.1%} reliability improvement")
        
        # Key focus areas
        if strategy['focus_areas']:
            focus_str = ", ".join(strategy['focus_areas'])
            reasoning_parts.append(f"Focus areas: {focus_str}")
        
        return ". ".join(reasoning_parts)
    
    def _generate_implementation_steps(
        self,
        strategy: Dict[str, Any],
        analysis: ReliabilityAnalysis
    ) -> List[str]:
        """Generate detailed implementation steps"""
        steps = []
        
        # Always start with baseline
        steps.append("Establish baseline reliability measurements")
        steps.append("Document current failure modes and recovery procedures")
        
        # Add strategy-specific steps
        for technique in strategy.get('reliability_techniques', []):
            if technique == "circuit_breaker_implementation":
                steps.append("Implement circuit breaker patterns for external dependencies")
            elif technique == "auto_scaling_configuration":
                steps.append("Configure auto-scaling based on reliability metrics")
            elif technique == "backup_strategy_implementation":
                steps.append("Implement comprehensive backup and recovery strategy")
            elif technique == "monitoring_enhancement":
                steps.append("Enhance monitoring with reliability-focused metrics")
            elif technique == "health_check_implementation":
                steps.append("Implement comprehensive health check endpoints")
            elif technique == "resource_management_optimization":
                steps.append("Optimize resource allocation and limits")
        
        # Add testing steps
        if strategy.get('testing_strategy', {}).get('chaos_engineering'):
            steps.append("Implement chaos engineering testing protocols")
        
        if strategy.get('testing_strategy', {}).get('disaster_recovery_drills'):
            steps.append("Conduct disaster recovery drills and validation")
        
        # Add validation steps
        steps.append("Validate reliability improvements through testing")
        steps.append("Document lessons learned and update procedures")
        
        return steps
    
    def _identify_monitoring_metrics(self, analysis: ReliabilityAnalysis) -> List[str]:
        """Identify key metrics to monitor for reliability"""
        metrics = [
            'uptime',
            'availability',
            'error_rate',
            'response_time',
            'failure_count',
            'recovery_time'
        ]
        
        # Add specific metrics based on gaps
        for gap in analysis.resilience_gaps:
            if "Database" in gap:
                metrics.extend(['database_connection_count', 'database_query_time'])
            elif "Network" in gap:
                metrics.extend(['network_latency', 'network_error_rate'])
            elif "Auto-scaling" in gap:
                metrics.extend(['cpu_utilization', 'memory_usage', 'request_queue_size'])
        
        return list(set(metrics))  # Remove duplicates
    
    def _store_analysis(self, analysis: ReliabilityAnalysis, recommendation: Dict[str, Any]):
        """Store analysis results for learning"""
        record = {
            'timestamp': time.time(),
            'reliability_score': analysis.reliability_score,
            'mtbf_estimate': analysis.mtbf_estimate,
            'mttr_estimate': analysis.mttr_estimate,
            'gap_count': len(analysis.resilience_gaps),
            'strategy': recommendation['strategy'],
            'confidence': recommendation['confidence']
        }
        
        self.reliability_history.append(record)
        
        # Keep only last 50 records
        if len(self.reliability_history) > 50:
            self.reliability_history = self.reliability_history[-50:]
    
    def _generate_fallback_recommendation(self) -> Dict[str, Any]:
        """Generate fallback recommendation when analysis fails"""
        return {
            'strategy': 'basic_reliability_monitoring',
            'confidence': 0.5,
            'reasoning': 'Reliability analysis failed, recommending basic monitoring approach',
            'expected_outcome': {
                'reliability_improvement': 0.1,
                'mtbf_improvement': 1.1,
                'mttr_improvement': 0.9,
                'success_probability': 0.7,
                'implementation_time': 8,
                'risk_reduction': 0.2
            },
            'risk_assessment': 'medium',
            'implementation_steps': [
                'Implement basic health checks',
                'Set up uptime monitoring',
                'Document failure procedures',
                'Establish backup procedures'
            ],
            'metrics_to_monitor': ['uptime', 'error_rate', 'response_time']
        }
    
    async def configure(self, config: Dict[str, Any]):
        """Configure expert parameters"""
        if 'targets' in config:
            self.targets.update(config['targets'])
        
        if 'failure_patterns' in config:
            self.failure_patterns.update(config['failure_patterns'])
        
        if 'recovery_patterns' in config:
            self.recovery_patterns.update(config['recovery_patterns'])
        
        self.logger.info(f"Reliability Expert configured with {len(config)} parameters")