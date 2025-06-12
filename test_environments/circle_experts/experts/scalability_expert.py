"""
Scalability Expert - Specialized in horizontal and vertical scaling
Load distribution optimization, capacity planning, and elastic scaling validation
"""

import asyncio
import logging
import time
import math
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class ScalingType(Enum):
    HORIZONTAL = "horizontal"
    VERTICAL = "vertical"
    ELASTIC = "elastic"
    HYBRID = "hybrid"


class LoadPattern(Enum):
    STEADY = "steady"
    BURST = "burst"
    SEASONAL = "seasonal"
    UNPREDICTABLE = "unpredictable"


@dataclass
class ScalabilityAnalysis:
    """Scalability analysis result"""
    current_capacity: int
    peak_capacity_needed: int
    bottleneck_components: List[str]
    scaling_opportunities: List[str]
    scalability_score: float
    load_pattern: LoadPattern
    resource_utilization: Dict[str, float]
    scaling_constraints: List[str]
    cost_efficiency: float


class ScalabilityExpert:
    """
    Expert specializing in horizontal and vertical scaling strategies
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.name = "Scalability Expert"
        self.specializations = [
            "horizontal_scaling",
            "vertical_scaling",
            "elastic_scaling",
            "load_distribution",
            "capacity_planning",
            "auto_scaling",
            "performance_scaling"
        ]
        
        # Scaling targets and thresholds
        self.scaling_thresholds = {
            'cpu_scale_out': 70,  # Scale out when CPU > 70%
            'cpu_scale_in': 30,   # Scale in when CPU < 30%
            'memory_scale_out': 80,  # Scale out when Memory > 80%
            'memory_scale_in': 40,   # Scale in when Memory < 40%
            'response_time_threshold': 200,  # ms
            'throughput_threshold': 1000,  # requests/sec
            'queue_length_threshold': 100,  # pending requests
            'utilization_target': 70  # Target utilization percentage
        }
        
        # Scaling patterns and strategies
        self.scaling_patterns = {
            'web_tier': ['horizontal', 'load_balancing', 'session_affinity'],
            'app_tier': ['horizontal', 'vertical', 'microservices'],
            'database_tier': ['read_replicas', 'sharding', 'clustering'],
            'cache_tier': ['distributed_cache', 'cache_partitioning'],
            'storage_tier': ['distributed_storage', 'tiered_storage']
        }
        
        # Cost factors for different scaling approaches
        self.cost_factors = {
            'horizontal_scaling': {'setup_cost': 0.3, 'operational_cost': 1.0},
            'vertical_scaling': {'setup_cost': 0.1, 'operational_cost': 1.2},
            'elastic_scaling': {'setup_cost': 0.5, 'operational_cost': 0.8},
            'hybrid_scaling': {'setup_cost': 0.4, 'operational_cost': 0.9}
        }
        
        # Historical scaling data
        self.scaling_history: List[Dict[str, Any]] = []
        
    async def analyze_and_recommend(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze system scalability and provide expert recommendations
        """
        self.logger.info("Scalability Expert analyzing scaling requirements")
        
        try:
            # Extract scalability metrics
            current_metrics = context.get('current_metrics', {})
            system_state = context.get('system_state', {})
            historical_data = context.get('historical_data', [])
            objectives = context.get('objectives', [])
            
            # Perform comprehensive scalability analysis
            analysis = await self._analyze_scalability(
                current_metrics, system_state, historical_data
            )
            
            # Generate scalability strategy
            strategy = await self._generate_scalability_strategy(analysis, objectives)
            
            # Assess confidence based on data patterns and load characteristics
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
                'risk_assessment': self._assess_scaling_risk(analysis),
                'implementation_steps': implementation_steps,
                'metrics_to_monitor': metrics_to_monitor,
                'scalability_analysis': {
                    'current_capacity': analysis.current_capacity,
                    'peak_capacity_needed': analysis.peak_capacity_needed,
                    'bottleneck_components': analysis.bottleneck_components,
                    'scaling_opportunities': analysis.scaling_opportunities,
                    'scalability_score': analysis.scalability_score,
                    'load_pattern': analysis.load_pattern.value,
                    'resource_utilization': analysis.resource_utilization,
                    'scaling_constraints': analysis.scaling_constraints,
                    'cost_efficiency': analysis.cost_efficiency
                }
            }
            
            # Store analysis for learning
            self._store_analysis(analysis, recommendation)
            
            return recommendation
            
        except Exception as e:
            self.logger.error(f"Scalability analysis failed: {str(e)}")
            return self._generate_fallback_recommendation()
    
    async def _analyze_scalability(
        self,
        current_metrics: Dict[str, Any],
        system_state: Dict[str, Any],
        historical_data: List[Dict[str, Any]]
    ) -> ScalabilityAnalysis:
        """Comprehensive scalability analysis"""
        
        # Analyze current capacity and utilization
        current_capacity = self._calculate_current_capacity(current_metrics, system_state)
        resource_utilization = self._analyze_resource_utilization(current_metrics)
        
        # Predict peak capacity needed
        peak_capacity_needed = await self._predict_peak_capacity(historical_data, current_metrics)
        
        # Identify bottleneck components
        bottleneck_components = await self._identify_bottlenecks(current_metrics, system_state)
        
        # Find scaling opportunities
        scaling_opportunities = await self._identify_scaling_opportunities(
            current_metrics, system_state, historical_data
        )
        
        # Calculate scalability score
        scalability_score = self._calculate_scalability_score(
            current_metrics, system_state, resource_utilization
        )
        
        # Analyze load pattern
        load_pattern = self._analyze_load_pattern(historical_data)
        
        # Identify scaling constraints
        scaling_constraints = self._identify_scaling_constraints(system_state)
        
        # Calculate cost efficiency
        cost_efficiency = self._calculate_cost_efficiency(
            current_metrics, system_state, resource_utilization
        )
        
        return ScalabilityAnalysis(
            current_capacity=current_capacity,
            peak_capacity_needed=peak_capacity_needed,
            bottleneck_components=bottleneck_components,
            scaling_opportunities=scaling_opportunities,
            scalability_score=scalability_score,
            load_pattern=load_pattern,
            resource_utilization=resource_utilization,
            scaling_constraints=scaling_constraints,
            cost_efficiency=cost_efficiency
        )
    
    def _calculate_current_capacity(
        self,
        current_metrics: Dict[str, Any],
        system_state: Dict[str, Any]
    ) -> int:
        """Calculate current system capacity"""
        # Base capacity on current throughput and utilization
        current_throughput = current_metrics.get('throughput', 100)
        current_utilization = current_metrics.get('cpu_utilization', 50) / 100
        
        if current_utilization > 0:
            estimated_max_capacity = int(current_throughput / current_utilization)
        else:
            estimated_max_capacity = current_throughput * 2  # Conservative estimate
        
        # Consider instance count if available
        instance_count = system_state.get('instance_count', 1)
        per_instance_capacity = estimated_max_capacity // instance_count
        
        return max(100, estimated_max_capacity)  # Minimum 100 requests capacity
    
    def _analyze_resource_utilization(self, current_metrics: Dict[str, Any]) -> Dict[str, float]:
        """Analyze current resource utilization patterns"""
        return {
            'cpu': current_metrics.get('cpu_utilization', 50),
            'memory': current_metrics.get('memory_usage', 50),
            'disk_io': current_metrics.get('disk_io_utilization', 20),
            'network_io': current_metrics.get('network_utilization', 30),
            'connections': current_metrics.get('connection_utilization', 40)
        }
    
    async def _predict_peak_capacity(
        self,
        historical_data: List[Dict[str, Any]],
        current_metrics: Dict[str, Any]
    ) -> int:
        """Predict peak capacity requirements"""
        if len(historical_data) < 5:
            # Use current capacity with safety margin
            current_capacity = self._calculate_current_capacity(current_metrics, {})
            return int(current_capacity * 1.5)  # 50% safety margin
        
        # Analyze historical peaks
        historical_throughputs = [d.get('throughput', 100) for d in historical_data]
        max_historical = max(historical_throughputs)
        avg_historical = sum(historical_throughputs) / len(historical_throughputs)
        
        # Calculate growth trend
        recent_throughputs = historical_throughputs[-5:]
        growth_rate = self._calculate_growth_rate(recent_throughputs)
        
        # Predict peak with growth and seasonal factors
        predicted_peak = max_historical * (1 + growth_rate) * 1.3  # 30% seasonal buffer
        
        return max(int(predicted_peak), self._calculate_current_capacity(current_metrics, {}) * 1.2)
    
    async def _identify_bottlenecks(
        self,
        current_metrics: Dict[str, Any],
        system_state: Dict[str, Any]
    ) -> List[str]:
        """Identify scalability bottlenecks"""
        bottlenecks = []
        
        # CPU bottlenecks
        cpu_usage = current_metrics.get('cpu_utilization', 0)
        if cpu_usage > self.scaling_thresholds['cpu_scale_out']:
            bottlenecks.append(f"CPU bottleneck: {cpu_usage}% utilization")
        
        # Memory bottlenecks
        memory_usage = current_metrics.get('memory_usage', 0)
        if memory_usage > self.scaling_thresholds['memory_scale_out']:
            bottlenecks.append(f"Memory bottleneck: {memory_usage}% usage")
        
        # Database bottlenecks
        db_connections = current_metrics.get('database_connections', 0)
        max_db_connections = system_state.get('max_database_connections', 100)
        if db_connections > max_db_connections * 0.8:
            bottlenecks.append("Database connection pool bottleneck")
        
        db_query_time = current_metrics.get('database_query_time', 0)
        if db_query_time > 100:  # ms
            bottlenecks.append(f"Database query performance bottleneck: {db_query_time}ms")
        
        # Network bottlenecks
        network_utilization = current_metrics.get('network_utilization', 0)
        if network_utilization > 80:
            bottlenecks.append(f"Network I/O bottleneck: {network_utilization}% utilization")
        
        # Response time bottlenecks
        response_time = current_metrics.get('response_time', 0)
        if response_time > self.scaling_thresholds['response_time_threshold']:
            bottlenecks.append(f"Response time bottleneck: {response_time}ms")
        
        # Queue bottlenecks
        queue_length = current_metrics.get('request_queue_length', 0)
        if queue_length > self.scaling_thresholds['queue_length_threshold']:
            bottlenecks.append(f"Request queue bottleneck: {queue_length} pending")
        
        # Storage bottlenecks
        disk_usage = current_metrics.get('disk_usage', 0)
        if disk_usage > 85:
            bottlenecks.append(f"Disk storage bottleneck: {disk_usage}% usage")
        
        disk_io_wait = current_metrics.get('disk_io_wait', 0)
        if disk_io_wait > 20:
            bottlenecks.append(f"Disk I/O bottleneck: {disk_io_wait}% wait time")
        
        return bottlenecks
    
    async def _identify_scaling_opportunities(
        self,
        current_metrics: Dict[str, Any],
        system_state: Dict[str, Any],
        historical_data: List[Dict[str, Any]]
    ) -> List[str]:
        """Identify scaling opportunities"""
        opportunities = []
        
        # Horizontal scaling opportunities
        instance_count = system_state.get('instance_count', 1)
        if instance_count == 1:
            opportunities.append("Horizontal scaling opportunity: Single instance architecture")
        
        # Load balancing opportunities
        if not system_state.get('load_balancer', False):
            opportunities.append("Load balancing implementation opportunity")
        
        # Auto-scaling opportunities
        if not system_state.get('auto_scaling', False):
            opportunities.append("Auto-scaling implementation opportunity")
        
        # Microservices opportunities
        if system_state.get('architecture', 'monolith') == 'monolith':
            opportunities.append("Microservices decomposition opportunity")
        
        # Caching opportunities
        cache_hit_rate = current_metrics.get('cache_hit_rate', 0)
        if cache_hit_rate < 0.8:
            opportunities.append(f"Caching optimization opportunity: {cache_hit_rate:.1%} hit rate")
        
        # Database scaling opportunities
        if not system_state.get('database_replication', False):
            opportunities.append("Database read replica opportunity")
        
        if not system_state.get('database_sharding', False):
            db_utilization = current_metrics.get('database_cpu_utilization', 50)
            if db_utilization > 70:
                opportunities.append("Database sharding opportunity")
        
        # CDN opportunities
        if not system_state.get('cdn_enabled', False):
            opportunities.append("CDN implementation opportunity for static content")
        
        # Connection pooling opportunities
        if not system_state.get('connection_pooling', False):
            opportunities.append("Connection pooling optimization opportunity")
        
        # Elastic scaling based on patterns
        if len(historical_data) >= 10:
            load_variance = self._calculate_load_variance(historical_data)
            if load_variance > 0.3:  # High variance
                opportunities.append("Elastic scaling opportunity due to variable load patterns")
        
        # Resource optimization opportunities
        resource_utilization = self._analyze_resource_utilization(current_metrics)
        underutilized = [k for k, v in resource_utilization.items() if v < 30]
        if underutilized:
            opportunities.append(f"Resource optimization opportunity: underutilized {', '.join(underutilized)}")
        
        return opportunities
    
    def _calculate_scalability_score(
        self,
        current_metrics: Dict[str, Any],
        system_state: Dict[str, Any],
        resource_utilization: Dict[str, float]
    ) -> float:
        """Calculate overall scalability score (0-1)"""
        scores = []
        
        # Resource utilization efficiency (target around 70%)
        target_utilization = self.scaling_thresholds['utilization_target']
        utilization_scores = []
        for resource, usage in resource_utilization.items():
            # Score based on how close to target (penalty for over/under utilization)
            distance_from_target = abs(usage - target_utilization) / target_utilization
            utilization_score = max(0, 1 - distance_from_target)
            utilization_scores.append(utilization_score)
        
        avg_utilization_score = sum(utilization_scores) / len(utilization_scores)
        scores.append(avg_utilization_score * 0.3)  # 30% weight
        
        # Architecture scalability
        arch_score = 0.5  # Base score
        if system_state.get('load_balancer', False):
            arch_score += 0.1
        if system_state.get('auto_scaling', False):
            arch_score += 0.15
        if system_state.get('microservices', False):
            arch_score += 0.1
        if system_state.get('database_replication', False):
            arch_score += 0.1
        if system_state.get('caching_enabled', False):
            arch_score += 0.05
        
        scores.append(min(1.0, arch_score) * 0.25)  # 25% weight
        
        # Performance under load
        response_time = current_metrics.get('response_time', 100)
        response_score = max(0, min(1, (500 - response_time) / 500))
        scores.append(response_score * 0.2)  # 20% weight
        
        # Throughput efficiency
        current_throughput = current_metrics.get('throughput', 100)
        max_throughput = current_metrics.get('max_throughput', 200)
        throughput_score = min(1, current_throughput / max_throughput)
        scores.append(throughput_score * 0.15)  # 15% weight
        
        # Error rate under load
        error_rate = current_metrics.get('error_rate', 0)
        error_score = max(0, min(1, (0.05 - error_rate) / 0.05))
        scores.append(error_score * 0.1)  # 10% weight
        
        return sum(scores)
    
    def _analyze_load_pattern(self, historical_data: List[Dict[str, Any]]) -> LoadPattern:
        """Analyze load patterns from historical data"""
        if len(historical_data) < 10:
            return LoadPattern.UNPREDICTABLE
        
        throughputs = [d.get('throughput', 100) for d in historical_data]
        
        # Calculate variance
        variance = self._calculate_load_variance(historical_data)
        
        # Calculate periodicity (simple check for patterns)
        daily_patterns = self._check_daily_patterns(throughputs)
        weekly_patterns = self._check_weekly_patterns(throughputs)
        
        # Classify pattern
        if variance < 0.1:
            return LoadPattern.STEADY
        elif daily_patterns or weekly_patterns:
            return LoadPattern.SEASONAL
        elif self._check_burst_patterns(throughputs):
            return LoadPattern.BURST
        else:
            return LoadPattern.UNPREDICTABLE
    
    def _identify_scaling_constraints(self, system_state: Dict[str, Any]) -> List[str]:
        """Identify constraints that limit scaling"""
        constraints = []
        
        # Database constraints
        if not system_state.get('database_replication', False):
            constraints.append("Database single point of failure limits horizontal scaling")
        
        # Session state constraints
        if system_state.get('stateful_sessions', True):
            constraints.append("Stateful sessions limit horizontal scaling flexibility")
        
        # Shared storage constraints
        if system_state.get('shared_storage_dependency', False):
            constraints.append("Shared storage dependency creates scaling bottleneck")
        
        # License constraints
        if system_state.get('licensed_software', False):
            constraints.append("Software licensing costs may limit scaling")
        
        # Network constraints
        network_bandwidth = system_state.get('network_bandwidth_limit', 0)
        if network_bandwidth > 0:
            constraints.append(f"Network bandwidth limit: {network_bandwidth} Mbps")
        
        # Resource constraints
        if system_state.get('resource_quota_limits', False):
            constraints.append("Resource quota limits constrain scaling")
        
        # Geographic constraints
        if not system_state.get('multi_region_capability', False):
            constraints.append("Single region deployment limits geographic scaling")
        
        # Cost constraints
        if system_state.get('budget_constraints', False):
            constraints.append("Budget constraints limit scaling options")
        
        return constraints
    
    def _calculate_cost_efficiency(
        self,
        current_metrics: Dict[str, Any],
        system_state: Dict[str, Any],
        resource_utilization: Dict[str, float]
    ) -> float:
        """Calculate cost efficiency of current scaling approach"""
        # Base efficiency on resource utilization
        avg_utilization = sum(resource_utilization.values()) / len(resource_utilization)
        utilization_efficiency = avg_utilization / 100
        
        # Adjust for architecture efficiency
        arch_efficiency = 1.0
        if system_state.get('auto_scaling', False):
            arch_efficiency *= 1.1  # Auto-scaling improves efficiency
        if system_state.get('spot_instances', False):
            arch_efficiency *= 1.2  # Spot instances reduce cost
        if system_state.get('reserved_instances', False):
            arch_efficiency *= 1.1  # Reserved instances reduce cost
        
        # Consider over-provisioning penalty
        instance_count = system_state.get('instance_count', 1)
        min_required_instances = max(1, int(avg_utilization / 70))  # Target 70% utilization
        if instance_count > min_required_instances * 1.5:
            arch_efficiency *= 0.8  # Penalty for over-provisioning
        
        return min(1.0, utilization_efficiency * arch_efficiency)
    
    async def _generate_scalability_strategy(
        self,
        analysis: ScalabilityAnalysis,
        objectives: List[str]
    ) -> Dict[str, Any]:
        """Generate scalability strategy"""
        
        # Determine primary scaling approach
        capacity_gap = analysis.peak_capacity_needed / analysis.current_capacity
        
        if capacity_gap > 3.0:
            strategy_name = "aggressive_horizontal_scaling"
            scaling_type = ScalingType.HORIZONTAL
            priority = "critical"
        elif capacity_gap > 2.0:
            strategy_name = "hybrid_scaling_approach"
            scaling_type = ScalingType.HYBRID
            priority = "high"
        elif capacity_gap > 1.5:
            strategy_name = "elastic_scaling_optimization"
            scaling_type = ScalingType.ELASTIC
            priority = "medium"
        else:
            strategy_name = "vertical_scaling_optimization"
            scaling_type = ScalingType.VERTICAL
            priority = "low"
        
        # Adjust strategy based on load pattern
        if analysis.load_pattern == LoadPattern.BURST:
            strategy_name = "burst_ready_elastic_scaling"
            scaling_type = ScalingType.ELASTIC
        elif analysis.load_pattern == LoadPattern.SEASONAL:
            strategy_name = "predictive_scaling_strategy"
        
        # Define strategy details
        strategy = {
            'name': strategy_name,
            'scaling_type': scaling_type.value,
            'priority': priority,
            'target_capacity': analysis.peak_capacity_needed,
            'scaling_techniques': self._select_scaling_techniques(analysis),
            'implementation_phases': self._plan_implementation_phases(analysis),
            'expected_outcome': {
                'capacity_improvement': capacity_gap,
                'performance_improvement': self._estimate_performance_improvement(analysis),
                'cost_impact': self._estimate_cost_impact(analysis, scaling_type),
                'implementation_time': self._estimate_implementation_time(analysis),
                'success_probability': self._estimate_success_probability(analysis),
                'scalability_score_improvement': self._estimate_scalability_improvement(analysis)
            },
            'monitoring_strategy': {
                'key_metrics': self._define_scaling_metrics(),
                'auto_scaling_policies': self._define_auto_scaling_policies(analysis),
                'alerting_thresholds': self._define_alerting_thresholds()
            }
        }
        
        return strategy
    
    def _select_scaling_techniques(self, analysis: ScalabilityAnalysis) -> List[str]:
        """Select appropriate scaling techniques"""
        techniques = []
        
        # Based on bottlenecks
        for bottleneck in analysis.bottleneck_components:
            if "CPU" in bottleneck:
                techniques.extend(["horizontal_pod_autoscaling", "cpu_optimization"])
            elif "Memory" in bottleneck:
                techniques.extend(["memory_optimization", "vertical_scaling"])
            elif "Database" in bottleneck:
                techniques.extend(["read_replicas", "connection_pooling", "query_optimization"])
            elif "Network" in bottleneck:
                techniques.extend(["load_balancing", "cdn_implementation"])
            elif "Response time" in bottleneck:
                techniques.extend(["caching_strategy", "async_processing"])
        
        # Based on opportunities
        for opportunity in analysis.scaling_opportunities:
            if "Horizontal scaling" in opportunity:
                techniques.append("horizontal_scaling_implementation")
            elif "Auto-scaling" in opportunity:
                techniques.append("auto_scaling_configuration")
            elif "Microservices" in opportunity:
                techniques.append("microservices_decomposition")
            elif "Caching" in opportunity:
                techniques.append("distributed_caching")
            elif "Load balancing" in opportunity:
                techniques.append("load_balancer_setup")
        
        # Based on load pattern
        if analysis.load_pattern == LoadPattern.BURST:
            techniques.extend(["burst_scaling", "predictive_scaling"])
        elif analysis.load_pattern == LoadPattern.SEASONAL:
            techniques.extend(["scheduled_scaling", "capacity_planning"])
        
        return list(set(techniques))[:8]  # Limit and remove duplicates
    
    def _plan_implementation_phases(self, analysis: ScalabilityAnalysis) -> List[str]:
        """Plan implementation phases for scaling strategy"""
        phases = []
        
        # Phase 1: Foundation
        phases.append("Phase 1: Infrastructure preparation and monitoring setup")
        
        # Phase 2: Quick wins
        if analysis.cost_efficiency < 0.7:
            phases.append("Phase 2: Resource optimization and cost reduction")
        
        # Phase 3: Core scaling
        if len(analysis.bottleneck_components) > 2:
            phases.append("Phase 3: Bottleneck resolution and capacity expansion")
        else:
            phases.append("Phase 3: Capacity expansion implementation")
        
        # Phase 4: Automation
        phases.append("Phase 4: Auto-scaling and automation implementation")
        
        # Phase 5: Optimization
        phases.append("Phase 5: Performance optimization and fine-tuning")
        
        return phases
    
    def _estimate_performance_improvement(self, analysis: ScalabilityAnalysis) -> float:
        """Estimate expected performance improvement"""
        capacity_improvement = analysis.peak_capacity_needed / analysis.current_capacity
        bottleneck_count = len(analysis.bottleneck_components)
        
        # Base improvement from capacity increase
        base_improvement = min(0.5, (capacity_improvement - 1) * 0.2)
        
        # Additional improvement from bottleneck resolution
        bottleneck_improvement = min(0.3, bottleneck_count * 0.1)
        
        # Efficiency improvement from better scaling
        efficiency_improvement = (1 - analysis.scalability_score) * 0.4
        
        total_improvement = base_improvement + bottleneck_improvement + efficiency_improvement
        
        return min(0.8, total_improvement)  # Cap at 80% improvement
    
    def _estimate_cost_impact(self, analysis: ScalabilityAnalysis, scaling_type: ScalingType) -> Dict[str, float]:
        """Estimate cost impact of scaling strategy"""
        cost_factors = self.cost_factors[scaling_type.value]
        capacity_increase = analysis.peak_capacity_needed / analysis.current_capacity
        
        # Setup cost (one-time)
        setup_cost = cost_factors['setup_cost'] * capacity_increase
        
        # Operational cost increase
        operational_cost_increase = cost_factors['operational_cost'] * (capacity_increase - 1)
        
        # Cost efficiency improvement
        current_efficiency = analysis.cost_efficiency
        target_efficiency = min(0.9, current_efficiency + 0.2)
        efficiency_savings = (target_efficiency - current_efficiency) * 0.3
        
        return {
            'setup_cost_factor': setup_cost,
            'operational_cost_increase': operational_cost_increase,
            'efficiency_savings': efficiency_savings,
            'net_cost_impact': operational_cost_increase - efficiency_savings
        }
    
    def _estimate_implementation_time(self, analysis: ScalabilityAnalysis) -> int:
        """Estimate implementation time in hours"""
        base_time = 24  # 24 hours base
        
        # Add time based on capacity increase
        capacity_factor = (analysis.peak_capacity_needed / analysis.current_capacity - 1) * 20
        
        # Add time based on bottlenecks
        bottleneck_time = len(analysis.bottleneck_components) * 8
        
        # Add time based on constraints
        constraint_time = len(analysis.scaling_constraints) * 4
        
        # Add time based on opportunities (complexity)
        opportunity_time = len(analysis.scaling_opportunities) * 6
        
        total_time = base_time + capacity_factor + bottleneck_time + constraint_time + opportunity_time
        
        return min(200, int(total_time))  # Cap at 200 hours
    
    def _estimate_success_probability(self, analysis: ScalabilityAnalysis) -> float:
        """Estimate probability of successful scaling implementation"""
        base_probability = 0.8
        
        # Reduce probability based on constraints
        constraint_penalty = len(analysis.scaling_constraints) * 0.05
        base_probability -= constraint_penalty
        
        # Reduce probability based on complexity
        complexity = len(analysis.bottleneck_components) + len(analysis.scaling_opportunities)
        if complexity > 8:
            base_probability *= 0.8
        elif complexity > 5:
            base_probability *= 0.9
        
        # Adjust based on current scalability score
        if analysis.scalability_score < 0.5:
            base_probability *= 0.7  # Major changes needed
        elif analysis.scalability_score < 0.7:
            base_probability *= 0.85
        
        return max(0.5, base_probability)  # Minimum 50% probability
    
    def _estimate_scalability_improvement(self, analysis: ScalabilityAnalysis) -> float:
        """Estimate scalability score improvement"""
        current_score = analysis.scalability_score
        opportunity_count = len(analysis.scaling_opportunities)
        
        # Base improvement potential
        improvement_potential = (1 - current_score) * 0.6
        
        # Additional improvement from opportunities
        opportunity_improvement = min(0.3, opportunity_count * 0.05)
        
        total_improvement = improvement_potential + opportunity_improvement
        
        return min(0.5, total_improvement)  # Cap at 50% improvement
    
    def _define_scaling_metrics(self) -> List[str]:
        """Define key metrics for scaling monitoring"""
        return [
            'throughput',
            'response_time',
            'cpu_utilization',
            'memory_usage',
            'instance_count',
            'queue_length',
            'error_rate',
            'cost_per_request',
            'resource_efficiency'
        ]
    
    def _define_auto_scaling_policies(self, analysis: ScalabilityAnalysis) -> Dict[str, Any]:
        """Define auto-scaling policies"""
        return {
            'scale_out_cpu_threshold': self.scaling_thresholds['cpu_scale_out'],
            'scale_in_cpu_threshold': self.scaling_thresholds['cpu_scale_in'],
            'scale_out_memory_threshold': self.scaling_thresholds['memory_scale_out'],
            'scale_in_memory_threshold': self.scaling_thresholds['memory_scale_in'],
            'scale_out_response_time_threshold': self.scaling_thresholds['response_time_threshold'],
            'min_instances': max(1, analysis.current_capacity // 1000),
            'max_instances': max(10, analysis.peak_capacity_needed // 100),
            'scale_out_cooldown': 300,  # 5 minutes
            'scale_in_cooldown': 600   # 10 minutes
        }
    
    def _define_alerting_thresholds(self) -> Dict[str, Any]:
        """Define alerting thresholds for scaling events"""
        return {
            'high_cpu_alert': 85,
            'high_memory_alert': 90,
            'high_response_time_alert': 500,
            'low_throughput_alert': 50,
            'scaling_failure_alert': True,
            'cost_anomaly_alert': 1.5  # 50% cost increase
        }
    
    def _calculate_growth_rate(self, values: List[float]) -> float:
        """Calculate growth rate from time series data"""
        if len(values) < 2:
            return 0.0
        
        # Simple linear growth calculation
        start_value = values[0]
        end_value = values[-1]
        periods = len(values) - 1
        
        if start_value > 0:
            growth_rate = (end_value / start_value) ** (1 / periods) - 1
            return max(-0.5, min(2.0, growth_rate))  # Cap between -50% and 200%
        
        return 0.0
    
    def _calculate_load_variance(self, historical_data: List[Dict[str, Any]]) -> float:
        """Calculate load variance from historical data"""
        if len(historical_data) < 2:
            return 0.0
        
        throughputs = [d.get('throughput', 100) for d in historical_data]
        mean_throughput = sum(throughputs) / len(throughputs)
        
        if mean_throughput == 0:
            return 0.0
        
        variance = sum((t - mean_throughput) ** 2 for t in throughputs) / len(throughputs)
        coefficient_of_variation = (variance ** 0.5) / mean_throughput
        
        return coefficient_of_variation
    
    def _check_daily_patterns(self, throughputs: List[float]) -> bool:
        """Check for daily load patterns"""
        if len(throughputs) < 24:
            return False
        
        # Simple check for repeating patterns every 24 data points
        daily_cycles = len(throughputs) // 24
        if daily_cycles < 2:
            return False
        
        correlations = []
        for cycle in range(1, daily_cycles):
            cycle_data = throughputs[cycle * 24:(cycle + 1) * 24]
            base_data = throughputs[:24]
            
            if len(cycle_data) == 24:
                correlation = self._calculate_correlation(base_data, cycle_data)
                correlations.append(correlation)
        
        return len(correlations) > 0 and sum(correlations) / len(correlations) > 0.5
    
    def _check_weekly_patterns(self, throughputs: List[float]) -> bool:
        """Check for weekly load patterns"""
        if len(throughputs) < 168:  # 7 days * 24 hours
            return False
        
        # Similar to daily patterns but with weekly cycles
        weekly_cycles = len(throughputs) // 168
        if weekly_cycles < 2:
            return False
        
        correlations = []
        for cycle in range(1, weekly_cycles):
            cycle_data = throughputs[cycle * 168:(cycle + 1) * 168]
            base_data = throughputs[:168]
            
            if len(cycle_data) == 168:
                correlation = self._calculate_correlation(base_data, cycle_data)
                correlations.append(correlation)
        
        return len(correlations) > 0 and sum(correlations) / len(correlations) > 0.4
    
    def _check_burst_patterns(self, throughputs: List[float]) -> bool:
        """Check for burst load patterns"""
        if len(throughputs) < 10:
            return False
        
        mean_throughput = sum(throughputs) / len(throughputs)
        burst_threshold = mean_throughput * 2
        
        bursts = [t for t in throughputs if t > burst_threshold]
        burst_ratio = len(bursts) / len(throughputs)
        
        return 0.1 < burst_ratio < 0.3  # 10-30% of time in burst mode
    
    def _calculate_correlation(self, data1: List[float], data2: List[float]) -> float:
        """Calculate correlation between two data series"""
        if len(data1) != len(data2) or len(data1) == 0:
            return 0.0
        
        mean1 = sum(data1) / len(data1)
        mean2 = sum(data2) / len(data2)
        
        numerator = sum((x - mean1) * (y - mean2) for x, y in zip(data1, data2))
        
        sum_sq1 = sum((x - mean1) ** 2 for x in data1)
        sum_sq2 = sum((y - mean2) ** 2 for y in data2)
        
        denominator = (sum_sq1 * sum_sq2) ** 0.5
        
        if denominator == 0:
            return 0.0
        
        return numerator / denominator
    
    def _assess_scaling_risk(self, analysis: ScalabilityAnalysis) -> str:
        """Assess overall scaling risk level"""
        risk_score = 0
        
        # Risk based on capacity gap
        capacity_gap = analysis.peak_capacity_needed / analysis.current_capacity
        if capacity_gap > 3:
            risk_score += 3
        elif capacity_gap > 2:
            risk_score += 2
        elif capacity_gap > 1.5:
            risk_score += 1
        
        # Risk based on constraints
        risk_score += min(3, len(analysis.scaling_constraints))
        
        # Risk based on bottlenecks
        risk_score += min(2, len(analysis.bottleneck_components) // 2)
        
        # Risk based on cost efficiency
        if analysis.cost_efficiency < 0.5:
            risk_score += 2
        elif analysis.cost_efficiency < 0.7:
            risk_score += 1
        
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
        if len(historical_data) >= 20:
            base_confidence += 0.1
        elif len(historical_data) >= 10:
            base_confidence += 0.05
        
        # Increase confidence with more complete metrics
        key_metrics = ['throughput', 'cpu_utilization', 'memory_usage', 'response_time']
        metrics_coverage = sum(1 for metric in key_metrics if metric in current_metrics) / len(key_metrics)
        base_confidence += (metrics_coverage - 0.5) * 0.15
        
        # Reduce confidence for unpredictable load patterns
        if len(historical_data) >= 10:
            load_variance = self._calculate_load_variance(historical_data)
            if load_variance > 0.5:  # High variance
                base_confidence -= 0.1
        
        return min(0.95, max(0.5, base_confidence))
    
    def _generate_reasoning(
        self,
        analysis: ScalabilityAnalysis,
        strategy: Dict[str, Any]
    ) -> str:
        """Generate reasoning for the recommendation"""
        reasoning_parts = []
        
        # Analysis summary
        capacity_gap = analysis.peak_capacity_needed / analysis.current_capacity
        reasoning_parts.append(f"Scalability analysis shows {capacity_gap:.1f}x capacity increase needed")
        reasoning_parts.append(f"Current scalability score: {analysis.scalability_score:.2f}")
        reasoning_parts.append(f"Load pattern identified as: {analysis.load_pattern.value}")
        
        # Strategy justification
        reasoning_parts.append(f"Recommended {strategy['name']} strategy")
        reasoning_parts.append(f"Expected {strategy['expected_outcome']['performance_improvement']:.1%} performance improvement")
        
        # Key constraints
        if analysis.scaling_constraints:
            constraint_count = len(analysis.scaling_constraints)
            reasoning_parts.append(f"Identified {constraint_count} scaling constraints to address")
        
        return ". ".join(reasoning_parts)
    
    def _generate_implementation_steps(
        self,
        strategy: Dict[str, Any],
        analysis: ScalabilityAnalysis
    ) -> List[str]:
        """Generate detailed implementation steps"""
        steps = []
        
        # Always start with planning and baseline
        steps.append("Establish baseline capacity and performance measurements")
        steps.append("Plan scaling architecture and resource requirements")
        
        # Add strategy-specific steps
        for technique in strategy.get('scaling_techniques', []):
            if technique == "horizontal_scaling_implementation":
                steps.append("Implement horizontal scaling with load balancing")
            elif technique == "auto_scaling_configuration":
                steps.append("Configure auto-scaling policies and thresholds")
            elif technique == "microservices_decomposition":
                steps.append("Plan and implement microservices decomposition")
            elif technique == "distributed_caching":
                steps.append("Implement distributed caching layer")
            elif technique == "read_replicas":
                steps.append("Configure database read replicas")
            elif technique == "connection_pooling":
                steps.append("Optimize connection pooling configuration")
        
        # Add phase-specific steps
        for phase in strategy.get('implementation_phases', []):
            steps.append(f"Execute {phase}")
        
        # Add validation steps
        steps.append("Implement capacity testing and validation")
        steps.append("Monitor scaling behavior and optimize")
        steps.append("Document scaling procedures and lessons learned")
        
        return steps
    
    def _identify_monitoring_metrics(self, analysis: ScalabilityAnalysis) -> List[str]:
        """Identify key metrics to monitor during scaling"""
        metrics = self._define_scaling_metrics()
        
        # Add specific metrics based on bottlenecks
        for bottleneck in analysis.bottleneck_components:
            if "Database" in bottleneck:
                metrics.extend(['database_connections', 'database_query_time'])
            elif "Network" in bottleneck:
                metrics.extend(['network_utilization', 'bandwidth_usage'])
            elif "Queue" in bottleneck:
                metrics.extend(['queue_length', 'queue_processing_time'])
        
        # Add metrics based on load pattern
        if analysis.load_pattern == LoadPattern.BURST:
            metrics.extend(['burst_capacity_usage', 'scaling_events'])
        elif analysis.load_pattern == LoadPattern.SEASONAL:
            metrics.extend(['seasonal_trends', 'predictive_metrics'])
        
        return list(set(metrics))  # Remove duplicates
    
    def _store_analysis(self, analysis: ScalabilityAnalysis, recommendation: Dict[str, Any]):
        """Store analysis results for learning"""
        record = {
            'timestamp': time.time(),
            'current_capacity': analysis.current_capacity,
            'peak_capacity_needed': analysis.peak_capacity_needed,
            'scalability_score': analysis.scalability_score,
            'load_pattern': analysis.load_pattern.value,
            'cost_efficiency': analysis.cost_efficiency,
            'strategy': recommendation['strategy'],
            'confidence': recommendation['confidence']
        }
        
        self.scaling_history.append(record)
        
        # Keep only last 50 records
        if len(self.scaling_history) > 50:
            self.scaling_history = self.scaling_history[-50:]
    
    def _generate_fallback_recommendation(self) -> Dict[str, Any]:
        """Generate fallback recommendation when analysis fails"""
        return {
            'strategy': 'conservative_capacity_monitoring',
            'confidence': 0.5,
            'reasoning': 'Scalability analysis failed, recommending conservative monitoring approach',
            'expected_outcome': {
                'capacity_improvement': 1.2,
                'performance_improvement': 0.1,
                'cost_impact': {'net_cost_impact': 0.1},
                'implementation_time': 16,
                'success_probability': 0.8,
                'scalability_score_improvement': 0.1
            },
            'risk_assessment': 'low',
            'implementation_steps': [
                'Implement basic capacity monitoring',
                'Set up performance baselines',
                'Configure basic auto-scaling',
                'Monitor and adjust gradually'
            ],
            'metrics_to_monitor': ['throughput', 'response_time', 'cpu_utilization', 'memory_usage']
        }
    
    async def configure(self, config: Dict[str, Any]):
        """Configure expert parameters"""
        if 'scaling_thresholds' in config:
            self.scaling_thresholds.update(config['scaling_thresholds'])
        
        if 'scaling_patterns' in config:
            self.scaling_patterns.update(config['scaling_patterns'])
        
        if 'cost_factors' in config:
            self.cost_factors.update(config['cost_factors'])
        
        self.logger.info(f"Scalability Expert configured with {len(config)} parameters")