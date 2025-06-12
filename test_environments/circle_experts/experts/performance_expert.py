"""
Performance Expert - Specialized in performance optimization and testing
CPU, memory, I/O optimization strategies and bottleneck identification
"""

import asyncio
import logging
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import statistics


class PerformanceMetric(Enum):
    CPU_UTILIZATION = "cpu_utilization"
    MEMORY_USAGE = "memory_usage"
    DISK_IO = "disk_io"
    NETWORK_IO = "network_io"
    RESPONSE_TIME = "response_time"
    THROUGHPUT = "throughput"
    LATENCY = "latency"
    GARBAGE_COLLECTION = "gc_time"


@dataclass
class PerformanceAnalysis:
    """Performance analysis result"""
    bottlenecks: List[str]
    optimization_opportunities: List[str]
    performance_score: float
    critical_metrics: Dict[str, float]
    recommendations: List[str]
    risk_level: str


class PerformanceExpert:
    """
    Expert specializing in performance optimization and analysis
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.name = "Performance Expert"
        self.specializations = [
            "cpu_optimization",
            "memory_management",
            "io_optimization",
            "response_time_improvement",
            "throughput_optimization",
            "bottleneck_identification"
        ]
        
        # Performance thresholds
        self.thresholds = {
            'cpu_utilization': {'warning': 70, 'critical': 85},
            'memory_usage': {'warning': 75, 'critical': 90},
            'response_time': {'warning': 200, 'critical': 500},  # milliseconds
            'throughput': {'warning': 100, 'critical': 50},  # requests/sec
            'error_rate': {'warning': 0.01, 'critical': 0.05}
        }
        
        # Historical performance data
        self.performance_history: List[Dict[str, Any]] = []
        self.optimization_patterns: Dict[str, List[str]] = {}
        
    async def analyze_and_recommend(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze system performance and provide expert recommendations
        """
        self.logger.info("Performance Expert analyzing system state")
        
        try:
            # Extract performance metrics
            current_metrics = context.get('current_metrics', {})
            system_state = context.get('system_state', {})
            historical_data = context.get('historical_data', [])
            objectives = context.get('objectives', [])
            
            # Perform comprehensive performance analysis
            analysis = await self._analyze_performance(
                current_metrics, system_state, historical_data
            )
            
            # Generate performance strategy
            strategy = await self._generate_performance_strategy(analysis, objectives)
            
            # Assess confidence based on data quality and patterns
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
                'risk_assessment': analysis.risk_level,
                'implementation_steps': implementation_steps,
                'metrics_to_monitor': metrics_to_monitor,
                'performance_analysis': {
                    'bottlenecks': analysis.bottlenecks,
                    'optimization_opportunities': analysis.optimization_opportunities,
                    'performance_score': analysis.performance_score,
                    'critical_metrics': analysis.critical_metrics
                }
            }
            
            # Store analysis for learning
            self._store_analysis(analysis, recommendation)
            
            return recommendation
            
        except Exception as e:
            self.logger.error(f"Performance analysis failed: {str(e)}")
            return self._generate_fallback_recommendation()
    
    async def _analyze_performance(
        self,
        current_metrics: Dict[str, Any],
        system_state: Dict[str, Any],
        historical_data: List[Dict[str, Any]]
    ) -> PerformanceAnalysis:
        """Comprehensive performance analysis"""
        
        # Identify bottlenecks
        bottlenecks = await self._identify_bottlenecks(current_metrics, system_state)
        
        # Find optimization opportunities
        optimization_opportunities = await self._find_optimization_opportunities(
            current_metrics, historical_data
        )
        
        # Calculate performance score
        performance_score = self._calculate_performance_score(current_metrics)
        
        # Extract critical metrics
        critical_metrics = self._extract_critical_metrics(current_metrics)
        
        # Generate recommendations
        recommendations = await self._generate_performance_recommendations(
            bottlenecks, optimization_opportunities, critical_metrics
        )
        
        # Assess risk level
        risk_level = self._assess_risk_level(bottlenecks, critical_metrics)
        
        return PerformanceAnalysis(
            bottlenecks=bottlenecks,
            optimization_opportunities=optimization_opportunities,
            performance_score=performance_score,
            critical_metrics=critical_metrics,
            recommendations=recommendations,
            risk_level=risk_level
        )
    
    async def _identify_bottlenecks(
        self,
        current_metrics: Dict[str, Any],
        system_state: Dict[str, Any]
    ) -> List[str]:
        """Identify performance bottlenecks"""
        bottlenecks = []
        
        # CPU bottlenecks
        cpu_usage = current_metrics.get('cpu_utilization', 0)
        if cpu_usage > self.thresholds['cpu_utilization']['critical']:
            bottlenecks.append(f"Critical CPU bottleneck: {cpu_usage}% utilization")
        elif cpu_usage > self.thresholds['cpu_utilization']['warning']:
            bottlenecks.append(f"CPU pressure detected: {cpu_usage}% utilization")
        
        # Memory bottlenecks
        memory_usage = current_metrics.get('memory_usage', 0)
        if memory_usage > self.thresholds['memory_usage']['critical']:
            bottlenecks.append(f"Critical memory bottleneck: {memory_usage}% usage")
        elif memory_usage > self.thresholds['memory_usage']['warning']:
            bottlenecks.append(f"Memory pressure detected: {memory_usage}% usage")
        
        # Response time bottlenecks
        response_time = current_metrics.get('response_time', 0)
        if response_time > self.thresholds['response_time']['critical']:
            bottlenecks.append(f"Critical response time: {response_time}ms")
        elif response_time > self.thresholds['response_time']['warning']:
            bottlenecks.append(f"Elevated response time: {response_time}ms")
        
        # Throughput bottlenecks
        throughput = current_metrics.get('throughput', 0)
        if throughput < self.thresholds['throughput']['critical']:
            bottlenecks.append(f"Critical throughput degradation: {throughput} req/s")
        elif throughput < self.thresholds['throughput']['warning']:
            bottlenecks.append(f"Throughput below optimal: {throughput} req/s")
        
        # I/O bottlenecks
        disk_io = current_metrics.get('disk_io_wait', 0)
        if disk_io > 20:  # High I/O wait
            bottlenecks.append(f"Disk I/O bottleneck: {disk_io}% wait time")
        
        network_io = current_metrics.get('network_utilization', 0)
        if network_io > 80:
            bottlenecks.append(f"Network I/O bottleneck: {network_io}% utilization")
        
        return bottlenecks
    
    async def _find_optimization_opportunities(
        self,
        current_metrics: Dict[str, Any],
        historical_data: List[Dict[str, Any]]
    ) -> List[str]:
        """Find performance optimization opportunities"""
        opportunities = []
        
        # Analyze trends
        if len(historical_data) >= 5:
            # CPU optimization opportunities
            cpu_trend = self._calculate_trend([d.get('cpu_utilization', 0) for d in historical_data[-5:]])
            if cpu_trend > 0.1:  # Increasing trend
                opportunities.append("CPU usage trending upward - consider optimization")
            
            # Memory optimization opportunities
            memory_trend = self._calculate_trend([d.get('memory_usage', 0) for d in historical_data[-5:]])
            if memory_trend > 0.1:
                opportunities.append("Memory usage trending upward - potential memory leak")
            
            # Response time patterns
            response_times = [d.get('response_time', 0) for d in historical_data[-10:]]
            if len(response_times) > 5:
                avg_response_time = statistics.mean(response_times)
                if avg_response_time > 100:
                    opportunities.append("Response time consistently high - caching opportunity")
        
        # Resource utilization opportunities
        cpu_usage = current_metrics.get('cpu_utilization', 0)
        if cpu_usage < 30:
            opportunities.append("Low CPU utilization - opportunity for workload consolidation")
        
        memory_usage = current_metrics.get('memory_usage', 0)
        if memory_usage < 40:
            opportunities.append("Low memory utilization - opportunity for memory optimization")
        
        # Concurrency opportunities
        concurrent_requests = current_metrics.get('concurrent_requests', 0)
        max_capacity = current_metrics.get('max_capacity', 1000)
        if concurrent_requests < max_capacity * 0.5:
            opportunities.append("Low concurrency utilization - opportunity for load increase")
        
        return opportunities
    
    def _calculate_performance_score(self, current_metrics: Dict[str, Any]) -> float:
        """Calculate overall performance score (0-1)"""
        scores = []
        
        # CPU score (inverted - lower usage is better up to a point)
        cpu_usage = current_metrics.get('cpu_utilization', 50)
        cpu_score = max(0, min(1, (100 - cpu_usage) / 100))
        scores.append(cpu_score * 0.2)  # 20% weight
        
        # Memory score
        memory_usage = current_metrics.get('memory_usage', 50)
        memory_score = max(0, min(1, (100 - memory_usage) / 100))
        scores.append(memory_score * 0.2)  # 20% weight
        
        # Response time score
        response_time = current_metrics.get('response_time', 100)
        response_score = max(0, min(1, (500 - response_time) / 500))
        scores.append(response_score * 0.3)  # 30% weight
        
        # Throughput score
        throughput = current_metrics.get('throughput', 100)
        max_throughput = current_metrics.get('max_throughput', 200)
        throughput_score = min(1, throughput / max_throughput)
        scores.append(throughput_score * 0.2)  # 20% weight
        
        # Error rate score
        error_rate = current_metrics.get('error_rate', 0)
        error_score = max(0, min(1, (0.05 - error_rate) / 0.05))
        scores.append(error_score * 0.1)  # 10% weight
        
        return sum(scores)
    
    def _extract_critical_metrics(self, current_metrics: Dict[str, Any]) -> Dict[str, float]:
        """Extract critical performance metrics"""
        critical_metrics = {}
        
        # Always include core performance metrics
        for metric in ['cpu_utilization', 'memory_usage', 'response_time', 'throughput', 'error_rate']:
            if metric in current_metrics:
                critical_metrics[metric] = current_metrics[metric]
        
        # Add derived metrics
        if 'response_time' in current_metrics and 'throughput' in current_metrics:
            # Performance efficiency score
            response_time = current_metrics['response_time']
            throughput = current_metrics['throughput']
            efficiency = throughput / max(response_time, 1)  # Avoid division by zero
            critical_metrics['performance_efficiency'] = efficiency
        
        return critical_metrics
    
    async def _generate_performance_recommendations(
        self,
        bottlenecks: List[str],
        opportunities: List[str],
        critical_metrics: Dict[str, float]
    ) -> List[str]:
        """Generate specific performance recommendations"""
        recommendations = []
        
        # Bottleneck-based recommendations
        for bottleneck in bottlenecks:
            if "CPU" in bottleneck:
                recommendations.extend([
                    "Implement CPU-intensive task offloading",
                    "Optimize algorithm complexity",
                    "Consider horizontal scaling for CPU-bound workloads"
                ])
            elif "memory" in bottleneck:
                recommendations.extend([
                    "Implement memory pooling and reuse strategies",
                    "Review garbage collection settings",
                    "Investigate potential memory leaks"
                ])
            elif "response time" in bottleneck:
                recommendations.extend([
                    "Implement response caching strategies",
                    "Optimize database query performance",
                    "Review and optimize critical code paths"
                ])
            elif "throughput" in bottleneck:
                recommendations.extend([
                    "Implement connection pooling",
                    "Optimize request processing pipeline",
                    "Consider asynchronous processing patterns"
                ])
        
        # Opportunity-based recommendations
        for opportunity in opportunities:
            if "caching" in opportunity:
                recommendations.append("Implement intelligent caching layer")
            elif "consolidation" in opportunity:
                recommendations.append("Consider workload consolidation strategies")
            elif "memory optimization" in opportunity:
                recommendations.append("Optimize memory allocation patterns")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations[:10]  # Limit to top 10
    
    def _assess_risk_level(self, bottlenecks: List[str], critical_metrics: Dict[str, float]) -> str:
        """Assess performance risk level"""
        critical_bottlenecks = sum(1 for b in bottlenecks if "Critical" in b)
        warning_bottlenecks = len(bottlenecks) - critical_bottlenecks
        
        # Check critical metrics
        cpu_usage = critical_metrics.get('cpu_utilization', 0)
        memory_usage = critical_metrics.get('memory_usage', 0)
        error_rate = critical_metrics.get('error_rate', 0)
        
        if critical_bottlenecks > 2 or cpu_usage > 90 or memory_usage > 95 or error_rate > 0.1:
            return "critical"
        elif critical_bottlenecks > 0 or warning_bottlenecks > 3 or cpu_usage > 80 or memory_usage > 85:
            return "high"
        elif warning_bottlenecks > 0 or cpu_usage > 70 or memory_usage > 75:
            return "medium"
        else:
            return "low"
    
    async def _generate_performance_strategy(
        self,
        analysis: PerformanceAnalysis,
        objectives: List[str]
    ) -> Dict[str, Any]:
        """Generate performance optimization strategy"""
        
        # Determine strategy based on analysis
        if analysis.performance_score < 0.3:
            strategy_name = "emergency_optimization"
            priority = "critical"
        elif analysis.performance_score < 0.6:
            strategy_name = "aggressive_optimization"
            priority = "high"
        elif analysis.performance_score < 0.8:
            strategy_name = "targeted_optimization"
            priority = "medium"
        else:
            strategy_name = "fine_tuning"
            priority = "low"
        
        # Define strategy details
        strategy = {
            'name': strategy_name,
            'priority': priority,
            'focus_areas': self._determine_focus_areas(analysis),
            'optimization_techniques': self._select_optimization_techniques(analysis),
            'expected_outcome': {
                'performance_improvement': self._estimate_improvement(analysis),
                'success_probability': self._estimate_success_probability(analysis),
                'implementation_time': self._estimate_implementation_time(analysis),
                'resource_requirements': self._estimate_resource_requirements(analysis)
            },
            'monitoring_strategy': {
                'key_metrics': ['cpu_utilization', 'memory_usage', 'response_time', 'throughput'],
                'monitoring_interval': 30,  # seconds
                'alert_thresholds': self.thresholds
            }
        }
        
        return strategy
    
    def _determine_focus_areas(self, analysis: PerformanceAnalysis) -> List[str]:
        """Determine optimization focus areas"""
        focus_areas = []
        
        for bottleneck in analysis.bottlenecks:
            if "CPU" in bottleneck:
                focus_areas.append("cpu_optimization")
            elif "memory" in bottleneck:
                focus_areas.append("memory_optimization")
            elif "response time" in bottleneck:
                focus_areas.append("latency_optimization")
            elif "throughput" in bottleneck:
                focus_areas.append("throughput_optimization")
            elif "I/O" in bottleneck:
                focus_areas.append("io_optimization")
        
        return list(set(focus_areas))  # Remove duplicates
    
    def _select_optimization_techniques(self, analysis: PerformanceAnalysis) -> List[str]:
        """Select appropriate optimization techniques"""
        techniques = []
        
        # Based on bottlenecks
        for bottleneck in analysis.bottlenecks:
            if "CPU" in bottleneck:
                techniques.extend(["algorithm_optimization", "parallel_processing", "cpu_affinity"])
            elif "memory" in bottleneck:
                techniques.extend(["memory_pooling", "garbage_collection_tuning", "memory_profiling"])
            elif "response time" in bottleneck:
                techniques.extend(["caching", "query_optimization", "code_profiling"])
            elif "throughput" in bottleneck:
                techniques.extend(["connection_pooling", "async_processing", "load_balancing"])
        
        # Based on opportunities
        for opportunity in analysis.optimization_opportunities:
            if "caching" in opportunity:
                techniques.append("intelligent_caching")
            elif "consolidation" in opportunity:
                techniques.append("workload_consolidation")
        
        return list(set(techniques))[:8]  # Limit and remove duplicates
    
    def _estimate_improvement(self, analysis: PerformanceAnalysis) -> float:
        """Estimate expected performance improvement"""
        current_score = analysis.performance_score
        bottleneck_count = len(analysis.bottlenecks)
        
        # Base improvement estimation
        if current_score < 0.3:
            base_improvement = 0.4  # Up to 40% improvement possible
        elif current_score < 0.6:
            base_improvement = 0.3  # Up to 30% improvement
        elif current_score < 0.8:
            base_improvement = 0.2  # Up to 20% improvement
        else:
            base_improvement = 0.1  # Up to 10% improvement
        
        # Adjust based on bottlenecks
        bottleneck_factor = min(1.0, bottleneck_count * 0.1)
        estimated_improvement = base_improvement * (1 + bottleneck_factor)
        
        return min(0.5, estimated_improvement)  # Cap at 50% improvement
    
    def _estimate_success_probability(self, analysis: PerformanceAnalysis) -> float:
        """Estimate probability of successful optimization"""
        base_probability = 0.8
        
        # Reduce probability based on risk
        if analysis.risk_level == "critical":
            base_probability *= 0.7
        elif analysis.risk_level == "high":
            base_probability *= 0.8
        elif analysis.risk_level == "medium":
            base_probability *= 0.9
        
        # Adjust based on bottleneck complexity
        complex_bottlenecks = sum(1 for b in analysis.bottlenecks if any(term in b for term in ["Critical", "I/O", "network"]))
        if complex_bottlenecks > 2:
            base_probability *= 0.8
        
        return max(0.5, base_probability)  # Minimum 50% probability
    
    def _estimate_implementation_time(self, analysis: PerformanceAnalysis) -> int:
        """Estimate implementation time in hours"""
        base_time = 8  # 8 hours base
        
        # Add time based on bottlenecks
        bottleneck_time = len(analysis.bottlenecks) * 4
        
        # Add time based on optimization opportunities
        opportunity_time = len(analysis.optimization_opportunities) * 2
        
        total_time = base_time + bottleneck_time + opportunity_time
        
        return min(80, total_time)  # Cap at 80 hours
    
    def _estimate_resource_requirements(self, analysis: PerformanceAnalysis) -> Dict[str, Any]:
        """Estimate resource requirements for optimization"""
        return {
            'cpu_overhead': 5,  # 5% CPU overhead during optimization
            'memory_overhead': 10,  # 10% memory overhead
            'disk_space_mb': 500,  # 500MB for tools and logs
            'network_bandwidth_mbps': 10,  # 10Mbps for monitoring
            'team_size': min(3, max(1, len(analysis.bottlenecks)))
        }
    
    def _calculate_confidence(
        self,
        current_metrics: Dict[str, Any],
        historical_data: List[Dict[str, Any]]
    ) -> float:
        """Calculate confidence in the recommendation"""
        base_confidence = 0.7
        
        # Increase confidence with more data
        if len(historical_data) >= 10:
            base_confidence += 0.1
        elif len(historical_data) >= 5:
            base_confidence += 0.05
        
        # Increase confidence with more complete metrics
        key_metrics = ['cpu_utilization', 'memory_usage', 'response_time', 'throughput']
        metrics_coverage = sum(1 for metric in key_metrics if metric in current_metrics) / len(key_metrics)
        base_confidence += (metrics_coverage - 0.5) * 0.2
        
        return min(0.95, max(0.4, base_confidence))
    
    def _generate_reasoning(
        self,
        analysis: PerformanceAnalysis,
        strategy: Dict[str, Any]
    ) -> str:
        """Generate reasoning for the recommendation"""
        reasoning_parts = []
        
        # Analysis summary
        reasoning_parts.append(f"Performance analysis revealed {len(analysis.bottlenecks)} bottlenecks")
        reasoning_parts.append(f"Current performance score: {analysis.performance_score:.2f}")
        reasoning_parts.append(f"Risk level assessed as: {analysis.risk_level}")
        
        # Strategy justification
        reasoning_parts.append(f"Recommended {strategy['name']} strategy")
        reasoning_parts.append(f"Expected improvement: {strategy['expected_outcome']['performance_improvement']:.1%}")
        
        # Key focus areas
        if strategy['focus_areas']:
            focus_str = ", ".join(strategy['focus_areas'])
            reasoning_parts.append(f"Primary focus areas: {focus_str}")
        
        return ". ".join(reasoning_parts)
    
    def _generate_implementation_steps(
        self,
        strategy: Dict[str, Any],
        analysis: PerformanceAnalysis
    ) -> List[str]:
        """Generate detailed implementation steps"""
        steps = []
        
        # Always start with assessment
        steps.append("Establish baseline performance measurements")
        steps.append("Set up enhanced monitoring for optimization tracking")
        
        # Add strategy-specific steps
        for technique in strategy.get('optimization_techniques', []):
            if technique == "algorithm_optimization":
                steps.append("Profile and optimize critical algorithm paths")
            elif technique == "memory_pooling":
                steps.append("Implement memory pooling for frequent allocations")
            elif technique == "caching":
                steps.append("Design and implement intelligent caching layer")
            elif technique == "connection_pooling":
                steps.append("Configure optimal connection pooling parameters")
            elif technique == "async_processing":
                steps.append("Convert synchronous operations to asynchronous")
        
        # Add verification steps
        steps.append("Implement gradual rollout with performance validation")
        steps.append("Monitor and validate performance improvements")
        steps.append("Document optimization results and lessons learned")
        
        return steps
    
    def _identify_monitoring_metrics(self, analysis: PerformanceAnalysis) -> List[str]:
        """Identify key metrics to monitor during optimization"""
        metrics = [
            'cpu_utilization',
            'memory_usage',
            'response_time',
            'throughput',
            'error_rate'
        ]
        
        # Add specific metrics based on bottlenecks
        for bottleneck in analysis.bottlenecks:
            if "I/O" in bottleneck:
                metrics.extend(['disk_io_wait', 'network_utilization'])
            elif "garbage collection" in bottleneck:
                metrics.append('gc_time')
            elif "database" in bottleneck:
                metrics.append('db_query_time')
        
        return list(set(metrics))  # Remove duplicates
    
    def _calculate_trend(self, values: List[float]) -> float:
        """Calculate trend direction and magnitude"""
        if len(values) < 2:
            return 0.0
        
        # Simple linear trend calculation
        n = len(values)
        sum_x = sum(range(n))
        sum_y = sum(values)
        sum_xy = sum(i * y for i, y in enumerate(values))
        sum_x2 = sum(i * i for i in range(n))
        
        if n * sum_x2 - sum_x * sum_x == 0:
            return 0.0
        
        slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
        return slope
    
    def _store_analysis(self, analysis: PerformanceAnalysis, recommendation: Dict[str, Any]):
        """Store analysis results for learning"""
        record = {
            'timestamp': time.time(),
            'performance_score': analysis.performance_score,
            'bottleneck_count': len(analysis.bottlenecks),
            'strategy': recommendation['strategy'],
            'confidence': recommendation['confidence'],
            'risk_level': analysis.risk_level
        }
        
        self.performance_history.append(record)
        
        # Keep only last 50 records
        if len(self.performance_history) > 50:
            self.performance_history = self.performance_history[-50:]
    
    def _generate_fallback_recommendation(self) -> Dict[str, Any]:
        """Generate fallback recommendation when analysis fails"""
        return {
            'strategy': 'conservative_monitoring',
            'confidence': 0.4,
            'reasoning': 'Performance analysis failed, recommending conservative monitoring approach',
            'expected_outcome': {
                'performance_improvement': 0.05,
                'success_probability': 0.7,
                'implementation_time': 4,
                'resource_requirements': {'cpu_overhead': 2, 'memory_overhead': 5}
            },
            'risk_assessment': 'low',
            'implementation_steps': [
                'Implement basic performance monitoring',
                'Collect baseline metrics for 24 hours',
                'Identify obvious bottlenecks through observation',
                'Apply conservative optimizations'
            ],
            'metrics_to_monitor': ['cpu_utilization', 'memory_usage', 'response_time']
        }
    
    async def configure(self, config: Dict[str, Any]):
        """Configure expert parameters"""
        if 'thresholds' in config:
            self.thresholds.update(config['thresholds'])
        
        if 'specializations' in config:
            self.specializations = config['specializations']
        
        self.logger.info(f"Performance Expert configured with {len(config)} parameters")