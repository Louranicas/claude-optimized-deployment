"""
Analysis Engine - Intelligent result analysis and interpretation
Advanced analytics for test results with expert-driven insights
"""

import asyncio
import logging
import time
import statistics
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import re


class AnalysisType(Enum):
    PERFORMANCE_ANALYSIS = "performance_analysis"
    RELIABILITY_ANALYSIS = "reliability_analysis"
    SCALABILITY_ANALYSIS = "scalability_analysis"
    SECURITY_ANALYSIS = "security_analysis"
    CHAOS_ANALYSIS = "chaos_analysis"
    TREND_ANALYSIS = "trend_analysis"
    COMPARATIVE_ANALYSIS = "comparative_analysis"
    ROOT_CAUSE_ANALYSIS = "root_cause_analysis"


class InsightLevel(Enum):
    CRITICAL = "critical"
    IMPORTANT = "important"
    NOTABLE = "notable"
    MINOR = "minor"


class TrendDirection(Enum):
    IMPROVING = "improving"
    STABLE = "stable"
    DEGRADING = "degrading"
    VOLATILE = "volatile"


@dataclass
class Insight:
    """Analysis insight definition"""
    insight_id: str
    category: str
    level: InsightLevel
    title: str
    description: str
    evidence: List[str]
    implications: List[str]
    recommendations: List[str]
    confidence: float
    affected_metrics: List[str]
    trend_direction: Optional[TrendDirection] = None


@dataclass
class AnalysisResult:
    """Result of intelligent analysis"""
    analysis_type: AnalysisType
    insights: List[Insight]
    summary: str
    key_findings: List[str]
    performance_score: float
    trend_analysis: Dict[str, TrendDirection]
    anomalies: List[Dict[str, Any]]
    correlations: List[Dict[str, Any]]
    recommendations: List[str]
    confidence_score: float


class AnalysisEngine:
    """
    Intelligent analysis engine for test results and system behavior
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.name = "Analysis Engine"
        
        # Analysis patterns and rules
        self.performance_patterns = {
            'response_time_degradation': {
                'condition': lambda metrics: self._check_response_time_trend(metrics),
                'severity': InsightLevel.IMPORTANT,
                'category': 'performance'
            },
            'throughput_decline': {
                'condition': lambda metrics: self._check_throughput_decline(metrics),
                'severity': InsightLevel.IMPORTANT,
                'category': 'performance'
            },
            'memory_leak': {
                'condition': lambda metrics: self._detect_memory_leak(metrics),
                'severity': InsightLevel.CRITICAL,
                'category': 'reliability'
            },
            'cpu_saturation': {
                'condition': lambda metrics: self._detect_cpu_saturation(metrics),
                'severity': InsightLevel.CRITICAL,
                'category': 'scalability'
            },
            'error_rate_spike': {
                'condition': lambda metrics: self._detect_error_spike(metrics),
                'severity': InsightLevel.CRITICAL,
                'category': 'reliability'
            }
        }
        
        # Correlation analysis rules
        self.correlation_rules = [
            {
                'name': 'response_time_cpu_correlation',
                'metrics': ['response_time', 'cpu_utilization'],
                'threshold': 0.7,
                'interpretation': 'High CPU utilization correlates with increased response times'
            },
            {
                'name': 'error_rate_memory_correlation',
                'metrics': ['error_rate', 'memory_usage'],
                'threshold': 0.6,
                'interpretation': 'Memory pressure correlates with increased error rates'
            },
            {
                'name': 'throughput_connection_correlation',
                'metrics': ['throughput', 'active_connections'],
                'threshold': 0.8,
                'interpretation': 'Throughput strongly correlates with connection pool utilization'
            }
        ]
        
        # Anomaly detection thresholds
        self.anomaly_thresholds = {
            'response_time': {'deviation_multiplier': 3.0, 'min_threshold': 1000},
            'error_rate': {'deviation_multiplier': 2.5, 'min_threshold': 0.01},
            'cpu_utilization': {'deviation_multiplier': 2.0, 'min_threshold': 10},
            'memory_usage': {'deviation_multiplier': 2.0, 'min_threshold': 10},
            'throughput': {'deviation_multiplier': 2.5, 'min_threshold': 10}
        }
        
        # Benchmark thresholds for scoring
        self.performance_benchmarks = {
            'response_time': {'excellent': 100, 'good': 300, 'fair': 1000, 'poor': 3000},
            'error_rate': {'excellent': 0.001, 'good': 0.01, 'fair': 0.05, 'poor': 0.1},
            'cpu_utilization': {'excellent': 50, 'good': 70, 'fair': 85, 'poor': 95},
            'memory_usage': {'excellent': 60, 'good': 75, 'fair': 90, 'poor': 95},
            'throughput': {'excellent': 1000, 'good': 500, 'fair': 200, 'poor': 100}
        }
        
        # Analysis history for pattern learning
        self.analysis_history: List[Dict[str, Any]] = []
        
    async def analyze_results(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main analysis method - performs comprehensive intelligent analysis
        """
        self.logger.info("Starting intelligent analysis of test results")
        
        try:
            # Extract analysis input data
            execution_results = analysis_data.get('execution_results', {})
            context = analysis_data.get('context', {})
            expert_expectations = analysis_data.get('expert_expectations', {})
            historical_patterns = analysis_data.get('historical_patterns', {})
            
            # Determine analysis types needed
            analysis_types = self._determine_analysis_types(execution_results, context)
            
            # Perform comprehensive analysis
            analysis_results = []
            for analysis_type in analysis_types:
                result = await self._perform_analysis_type(
                    analysis_type, execution_results, context, expert_expectations, historical_patterns
                )
                analysis_results.append(result)
            
            # Aggregate insights from all analyses
            all_insights = []
            for result in analysis_results:
                all_insights.extend(result.insights)
            
            # Perform cross-analysis correlation
            correlations = await self._perform_correlation_analysis(execution_results)
            
            # Detect anomalies
            anomalies = await self._detect_anomalies(execution_results)
            
            # Perform trend analysis
            trend_analysis = await self._perform_trend_analysis(execution_results, historical_patterns)
            
            # Generate overall insights and recommendations
            final_insights = await self._generate_final_insights(
                all_insights, correlations, anomalies, trend_analysis
            )
            
            # Calculate overall performance score
            performance_score = self._calculate_overall_performance_score(execution_results)
            
            # Generate summary and key findings
            summary = self._generate_analysis_summary(final_insights, performance_score)
            key_findings = self._extract_key_findings(final_insights)
            
            # Generate actionable recommendations
            recommendations = self._generate_recommendations(final_insights, context)
            
            # Calculate confidence score
            confidence_score = self._calculate_analysis_confidence(final_insights, execution_results)
            
            # Compile final analysis result
            final_analysis = {
                'insights': [self._insight_to_dict(insight) for insight in final_insights],
                'summary': summary,
                'key_findings': key_findings,
                'performance_score': performance_score,
                'trend_analysis': {k: v.value for k, v in trend_analysis.items()},
                'anomalies': anomalies,
                'correlations': correlations,
                'recommendations': recommendations,
                'confidence_score': confidence_score,
                'analysis_metadata': {
                    'timestamp': time.time(),
                    'analysis_types': [at.value for at in analysis_types],
                    'total_insights': len(final_insights),
                    'critical_insights': sum(1 for i in final_insights if i.level == InsightLevel.CRITICAL),
                    'data_quality_score': self._assess_data_quality(execution_results)
                }
            }
            
            # Store analysis for learning
            self._store_analysis(final_analysis, execution_results, context)
            
            self.logger.info(f"Analysis completed with {len(final_insights)} insights and {performance_score:.1f} performance score")
            return final_analysis
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {str(e)}")
            return self._generate_fallback_analysis()
    
    def _determine_analysis_types(
        self,
        execution_results: Dict[str, Any],
        context: Dict[str, Any]
    ) -> List[AnalysisType]:
        """Determine which types of analysis to perform"""
        analysis_types = [AnalysisType.PERFORMANCE_ANALYSIS]  # Always include performance
        
        # Add analysis types based on available data
        if 'error_metrics' in execution_results or 'failure_data' in execution_results:
            analysis_types.append(AnalysisType.RELIABILITY_ANALYSIS)
        
        if 'scaling_events' in execution_results or context.get('scalability_test', False):
            analysis_types.append(AnalysisType.SCALABILITY_ANALYSIS)
        
        if 'security_metrics' in execution_results or context.get('security_test', False):
            analysis_types.append(AnalysisType.SECURITY_ANALYSIS)
        
        if 'chaos_experiments' in execution_results or context.get('chaos_test', False):
            analysis_types.append(AnalysisType.CHAOS_ANALYSIS)
        
        # Always include trend analysis if we have time series data
        if self._has_time_series_data(execution_results):
            analysis_types.append(AnalysisType.TREND_ANALYSIS)
        
        return analysis_types
    
    async def _perform_analysis_type(
        self,
        analysis_type: AnalysisType,
        execution_results: Dict[str, Any],
        context: Dict[str, Any],
        expert_expectations: Dict[str, Any],
        historical_patterns: Dict[str, Any]
    ) -> AnalysisResult:
        """Perform specific type of analysis"""
        
        if analysis_type == AnalysisType.PERFORMANCE_ANALYSIS:
            return await self._performance_analysis(execution_results, expert_expectations)
        elif analysis_type == AnalysisType.RELIABILITY_ANALYSIS:
            return await self._reliability_analysis(execution_results, expert_expectations)
        elif analysis_type == AnalysisType.SCALABILITY_ANALYSIS:
            return await self._scalability_analysis(execution_results, expert_expectations)
        elif analysis_type == AnalysisType.SECURITY_ANALYSIS:
            return await self._security_analysis(execution_results, expert_expectations)
        elif analysis_type == AnalysisType.CHAOS_ANALYSIS:
            return await self._chaos_analysis(execution_results, expert_expectations)
        elif analysis_type == AnalysisType.TREND_ANALYSIS:
            return await self._trend_analysis(execution_results, historical_patterns)
        else:
            # Generic analysis
            return await self._generic_analysis(execution_results, expert_expectations)
    
    async def _performance_analysis(
        self,
        execution_results: Dict[str, Any],
        expert_expectations: Dict[str, Any]
    ) -> AnalysisResult:
        """Perform detailed performance analysis"""
        insights = []
        
        metrics = execution_results.get('metrics', {})
        
        # Response time analysis
        response_time = metrics.get('response_time', 0)
        expected_response_time = expert_expectations.get('performance_targets', {}).get('response_time', 500)
        
        if response_time > expected_response_time * 1.5:
            insights.append(Insight(
                insight_id=f"perf_response_{int(time.time())}",
                category="performance",
                level=InsightLevel.CRITICAL,
                title="Response Time Exceeds Expectations",
                description=f"Average response time of {response_time}ms significantly exceeds target of {expected_response_time}ms",
                evidence=[f"Measured response time: {response_time}ms", f"Target: {expected_response_time}ms"],
                implications=["Poor user experience", "Potential performance bottlenecks", "May indicate resource constraints"],
                recommendations=["Investigate bottlenecks", "Optimize critical code paths", "Consider resource scaling"],
                confidence=0.9,
                affected_metrics=["response_time", "user_experience"],
                trend_direction=TrendDirection.DEGRADING
            ))
        
        # Throughput analysis
        throughput = metrics.get('throughput', 0)
        expected_throughput = expert_expectations.get('performance_targets', {}).get('throughput', 1000)
        
        if throughput < expected_throughput * 0.7:
            insights.append(Insight(
                insight_id=f"perf_throughput_{int(time.time())}",
                category="performance",
                level=InsightLevel.IMPORTANT,
                title="Throughput Below Target",
                description=f"System throughput of {throughput} req/s is below target of {expected_throughput} req/s",
                evidence=[f"Measured throughput: {throughput} req/s", f"Target: {expected_throughput} req/s"],
                implications=["Reduced system capacity", "Potential scalability issues"],
                recommendations=["Analyze bottlenecks", "Optimize request processing", "Consider parallel processing"],
                confidence=0.8,
                affected_metrics=["throughput", "capacity"],
                trend_direction=TrendDirection.DEGRADING
            ))
        
        # Resource utilization analysis
        cpu_usage = metrics.get('cpu_utilization', 0)
        memory_usage = metrics.get('memory_usage', 0)
        
        if cpu_usage > 85:
            insights.append(Insight(
                insight_id=f"perf_cpu_{int(time.time())}",
                category="performance",
                level=InsightLevel.CRITICAL if cpu_usage > 95 else InsightLevel.IMPORTANT,
                title="High CPU Utilization",
                description=f"CPU utilization of {cpu_usage}% indicates high resource pressure",
                evidence=[f"CPU utilization: {cpu_usage}%"],
                implications=["Performance degradation", "Reduced system responsiveness", "Potential for system instability"],
                recommendations=["Identify CPU-intensive operations", "Optimize algorithms", "Consider CPU scaling"],
                confidence=0.95,
                affected_metrics=["cpu_utilization", "response_time"],
                trend_direction=TrendDirection.DEGRADING
            ))
        
        if memory_usage > 90:
            insights.append(Insight(
                insight_id=f"perf_memory_{int(time.time())}",
                category="performance",
                level=InsightLevel.CRITICAL,
                title="High Memory Utilization",
                description=f"Memory usage of {memory_usage}% approaches critical levels",
                evidence=[f"Memory usage: {memory_usage}%"],
                implications=["Risk of out-of-memory errors", "Performance degradation", "System instability"],
                recommendations=["Investigate memory leaks", "Optimize memory usage", "Consider memory scaling"],
                confidence=0.9,
                affected_metrics=["memory_usage", "stability"],
                trend_direction=TrendDirection.DEGRADING
            ))
        
        # Calculate performance score
        performance_score = self._calculate_performance_score(metrics)
        
        return AnalysisResult(
            analysis_type=AnalysisType.PERFORMANCE_ANALYSIS,
            insights=insights,
            summary=f"Performance analysis identified {len(insights)} areas of concern",
            key_findings=[insight.title for insight in insights if insight.level in [InsightLevel.CRITICAL, InsightLevel.IMPORTANT]],
            performance_score=performance_score,
            trend_analysis={},
            anomalies=[],
            correlations=[],
            recommendations=[rec for insight in insights for rec in insight.recommendations],
            confidence_score=0.85
        )
    
    async def _reliability_analysis(
        self,
        execution_results: Dict[str, Any],
        expert_expectations: Dict[str, Any]
    ) -> AnalysisResult:
        """Perform reliability analysis"""
        insights = []
        
        metrics = execution_results.get('metrics', {})
        error_metrics = execution_results.get('error_metrics', {})
        
        # Error rate analysis
        error_rate = metrics.get('error_rate', 0)
        target_error_rate = expert_expectations.get('reliability_targets', {}).get('error_rate', 0.001)
        
        if error_rate > target_error_rate * 10:
            insights.append(Insight(
                insight_id=f"rel_error_{int(time.time())}",
                category="reliability",
                level=InsightLevel.CRITICAL,
                title="High Error Rate",
                description=f"Error rate of {error_rate:.3%} significantly exceeds target of {target_error_rate:.3%}",
                evidence=[f"Current error rate: {error_rate:.3%}", f"Target: {target_error_rate:.3%}"],
                implications=["Poor system reliability", "User experience degradation", "Potential data integrity issues"],
                recommendations=["Investigate error patterns", "Implement better error handling", "Add monitoring and alerting"],
                confidence=0.95,
                affected_metrics=["error_rate", "reliability"],
                trend_direction=TrendDirection.DEGRADING
            ))
        
        # Uptime analysis
        uptime = metrics.get('uptime', 1.0)
        target_uptime = expert_expectations.get('reliability_targets', {}).get('uptime', 0.999)
        
        if uptime < target_uptime:
            insights.append(Insight(
                insight_id=f"rel_uptime_{int(time.time())}",
                category="reliability",
                level=InsightLevel.IMPORTANT,
                title="Uptime Below Target",
                description=f"System uptime of {uptime:.3%} is below target of {target_uptime:.3%}",
                evidence=[f"Measured uptime: {uptime:.3%}", f"Target: {target_uptime:.3%}"],
                implications=["Service availability concerns", "Business impact", "SLA violations"],
                recommendations=["Implement redundancy", "Improve failure detection", "Enhance recovery procedures"],
                confidence=0.8,
                affected_metrics=["uptime", "availability"],
                trend_direction=TrendDirection.DEGRADING
            ))
        
        # Recovery time analysis
        recovery_time = metrics.get('recovery_time', 0)
        if recovery_time > 300:  # 5 minutes
            insights.append(Insight(
                insight_id=f"rel_recovery_{int(time.time())}",
                category="reliability",
                level=InsightLevel.IMPORTANT,
                title="Slow Recovery Time",
                description=f"Average recovery time of {recovery_time} seconds indicates slow failure recovery",
                evidence=[f"Recovery time: {recovery_time} seconds"],
                implications=["Extended downtime", "Poor user experience", "Business continuity risk"],
                recommendations=["Optimize recovery procedures", "Implement faster health checks", "Add automation"],
                confidence=0.75,
                affected_metrics=["recovery_time", "availability"],
                trend_direction=TrendDirection.DEGRADING
            ))
        
        performance_score = self._calculate_reliability_score(metrics)
        
        return AnalysisResult(
            analysis_type=AnalysisType.RELIABILITY_ANALYSIS,
            insights=insights,
            summary=f"Reliability analysis found {len(insights)} reliability concerns",
            key_findings=[insight.title for insight in insights],
            performance_score=performance_score,
            trend_analysis={},
            anomalies=[],
            correlations=[],
            recommendations=[rec for insight in insights for rec in insight.recommendations],
            confidence_score=0.8
        )
    
    async def _scalability_analysis(
        self,
        execution_results: Dict[str, Any],
        expert_expectations: Dict[str, Any]
    ) -> AnalysisResult:
        """Perform scalability analysis"""
        insights = []
        
        metrics = execution_results.get('metrics', {})
        scaling_events = execution_results.get('scaling_events', [])
        
        # Scaling efficiency analysis
        if scaling_events:
            avg_scale_time = statistics.mean([event.get('scale_time', 60) for event in scaling_events])
            target_scale_time = expert_expectations.get('scalability_targets', {}).get('scale_time', 30)
            
            if avg_scale_time > target_scale_time * 2:
                insights.append(Insight(
                    insight_id=f"scale_time_{int(time.time())}",
                    category="scalability",
                    level=InsightLevel.IMPORTANT,
                    title="Slow Scaling Response",
                    description=f"Average scaling time of {avg_scale_time:.1f}s exceeds target of {target_scale_time}s",
                    evidence=[f"Average scale time: {avg_scale_time:.1f}s", f"Target: {target_scale_time}s"],
                    implications=["Poor responsiveness to load changes", "Potential service degradation during scaling"],
                    recommendations=["Optimize scaling triggers", "Pre-warm resources", "Improve scaling automation"],
                    confidence=0.8,
                    affected_metrics=["scaling_time", "responsiveness"],
                    trend_direction=TrendDirection.DEGRADING
                ))
        
        # Resource saturation analysis
        max_load = metrics.get('max_load_handled', 0)
        target_load = expert_expectations.get('scalability_targets', {}).get('max_load', 10000)
        
        if max_load < target_load * 0.8:
            insights.append(Insight(
                insight_id=f"scale_capacity_{int(time.time())}",
                category="scalability",
                level=InsightLevel.IMPORTANT,
                title="Limited Scaling Capacity",
                description=f"Maximum load capacity of {max_load} is below target of {target_load}",
                evidence=[f"Max load handled: {max_load}", f"Target capacity: {target_load}"],
                implications=["Limited growth potential", "Capacity constraints under peak load"],
                recommendations=["Identify scaling bottlenecks", "Improve architecture scalability", "Add horizontal scaling"],
                confidence=0.75,
                affected_metrics=["capacity", "scalability"],
                trend_direction=TrendDirection.STABLE
            ))
        
        performance_score = self._calculate_scalability_score(metrics, scaling_events)
        
        return AnalysisResult(
            analysis_type=AnalysisType.SCALABILITY_ANALYSIS,
            insights=insights,
            summary=f"Scalability analysis identified {len(insights)} scalability considerations",
            key_findings=[insight.title for insight in insights],
            performance_score=performance_score,
            trend_analysis={},
            anomalies=[],
            correlations=[],
            recommendations=[rec for insight in insights for rec in insight.recommendations],
            confidence_score=0.75
        )
    
    async def _security_analysis(
        self,
        execution_results: Dict[str, Any],
        expert_expectations: Dict[str, Any]
    ) -> AnalysisResult:
        """Perform security analysis"""
        insights = []
        
        security_metrics = execution_results.get('security_metrics', {})
        
        # Security incident analysis
        security_incidents = security_metrics.get('security_incidents', 0)
        if security_incidents > 0:
            insights.append(Insight(
                insight_id=f"sec_incidents_{int(time.time())}",
                category="security",
                level=InsightLevel.CRITICAL,
                title="Security Incidents Detected",
                description=f"Detected {security_incidents} security incidents during testing",
                evidence=[f"Security incidents: {security_incidents}"],
                implications=["Security vulnerabilities exist", "Risk of data breaches", "Compliance violations"],
                recommendations=["Investigate security incidents", "Implement security patches", "Enhance monitoring"],
                confidence=0.95,
                affected_metrics=["security_incidents", "vulnerability_count"],
                trend_direction=TrendDirection.DEGRADING
            ))
        
        # Authentication failure analysis
        auth_failures = security_metrics.get('authentication_failures', 0)
        total_requests = security_metrics.get('total_requests', 1)
        auth_failure_rate = auth_failures / total_requests
        
        if auth_failure_rate > 0.05:  # 5% failure rate
            insights.append(Insight(
                insight_id=f"sec_auth_{int(time.time())}",
                category="security",
                level=InsightLevel.IMPORTANT,
                title="High Authentication Failure Rate",
                description=f"Authentication failure rate of {auth_failure_rate:.1%} indicates potential issues",
                evidence=[f"Auth failures: {auth_failures}", f"Failure rate: {auth_failure_rate:.1%}"],
                implications=["Authentication system stress", "Potential brute force attacks", "User experience issues"],
                recommendations=["Review authentication mechanisms", "Implement rate limiting", "Add monitoring"],
                confidence=0.8,
                affected_metrics=["authentication_failures", "security"],
                trend_direction=TrendDirection.DEGRADING
            ))
        
        performance_score = self._calculate_security_score(security_metrics)
        
        return AnalysisResult(
            analysis_type=AnalysisType.SECURITY_ANALYSIS,
            insights=insights,
            summary=f"Security analysis found {len(insights)} security concerns",
            key_findings=[insight.title for insight in insights],
            performance_score=performance_score,
            trend_analysis={},
            anomalies=[],
            correlations=[],
            recommendations=[rec for insight in insights for rec in insight.recommendations],
            confidence_score=0.8
        )
    
    async def _chaos_analysis(
        self,
        execution_results: Dict[str, Any],
        expert_expectations: Dict[str, Any]
    ) -> AnalysisResult:
        """Perform chaos engineering analysis"""
        insights = []
        
        chaos_experiments = execution_results.get('chaos_experiments', [])
        
        if chaos_experiments:
            # Recovery time analysis
            recovery_times = [exp.get('recovery_time', 0) for exp in chaos_experiments]
            avg_recovery_time = statistics.mean(recovery_times)
            target_recovery_time = expert_expectations.get('chaos_targets', {}).get('recovery_time', 60)
            
            if avg_recovery_time > target_recovery_time * 2:
                insights.append(Insight(
                    insight_id=f"chaos_recovery_{int(time.time())}",
                    category="chaos",
                    level=InsightLevel.IMPORTANT,
                    title="Slow Chaos Recovery",
                    description=f"Average recovery time of {avg_recovery_time:.1f}s exceeds target of {target_recovery_time}s",
                    evidence=[f"Average recovery: {avg_recovery_time:.1f}s", f"Target: {target_recovery_time}s"],
                    implications=["Poor resilience to failures", "Extended downtime during incidents"],
                    recommendations=["Improve failure detection", "Optimize recovery procedures", "Add automation"],
                    confidence=0.85,
                    affected_metrics=["recovery_time", "resilience"],
                    trend_direction=TrendDirection.DEGRADING
                ))
            
            # Failure handling analysis
            successful_recoveries = sum(1 for exp in chaos_experiments if exp.get('recovery_successful', False))
            recovery_success_rate = successful_recoveries / len(chaos_experiments)
            
            if recovery_success_rate < 0.9:
                insights.append(Insight(
                    insight_id=f"chaos_success_{int(time.time())}",
                    category="chaos",
                    level=InsightLevel.CRITICAL,
                    title="Poor Chaos Recovery Success Rate",
                    description=f"Recovery success rate of {recovery_success_rate:.1%} indicates resilience issues",
                    evidence=[f"Successful recoveries: {successful_recoveries}/{len(chaos_experiments)}"],
                    implications=["Poor system resilience", "Risk of cascading failures", "Inadequate fault tolerance"],
                    recommendations=["Implement circuit breakers", "Add redundancy", "Improve error handling"],
                    confidence=0.9,
                    affected_metrics=["recovery_success_rate", "resilience"],
                    trend_direction=TrendDirection.DEGRADING
                ))
        
        performance_score = self._calculate_chaos_score(chaos_experiments)
        
        return AnalysisResult(
            analysis_type=AnalysisType.CHAOS_ANALYSIS,
            insights=insights,
            summary=f"Chaos analysis evaluated {len(chaos_experiments)} experiments with {len(insights)} findings",
            key_findings=[insight.title for insight in insights],
            performance_score=performance_score,
            trend_analysis={},
            anomalies=[],
            correlations=[],
            recommendations=[rec for insight in insights for rec in insight.recommendations],
            confidence_score=0.8
        )
    
    async def _trend_analysis(
        self,
        execution_results: Dict[str, Any],
        historical_patterns: Dict[str, Any]
    ) -> AnalysisResult:
        """Perform trend analysis"""
        insights = []
        trends = {}
        
        # Analyze key metrics trends
        time_series_data = execution_results.get('time_series', {})
        
        for metric, values in time_series_data.items():
            if len(values) >= 5:  # Need minimum data points
                trend = self._calculate_trend_direction(values)
                trends[metric] = trend
                
                if trend == TrendDirection.DEGRADING and metric in ['response_time', 'error_rate', 'cpu_utilization']:
                    insights.append(Insight(
                        insight_id=f"trend_{metric}_{int(time.time())}",
                        category="trend",
                        level=InsightLevel.IMPORTANT,
                        title=f"Degrading {metric.replace('_', ' ').title()} Trend",
                        description=f"{metric.replace('_', ' ').title()} shows degrading trend over time",
                        evidence=[f"Trend direction: {trend.value}", f"Data points: {len(values)}"],
                        implications=["Performance degradation over time", "Potential systemic issues"],
                        recommendations=["Investigate root cause", "Monitor closely", "Consider preventive action"],
                        confidence=0.7,
                        affected_metrics=[metric],
                        trend_direction=trend
                    ))
        
        performance_score = 0.8  # Default trend score
        
        return AnalysisResult(
            analysis_type=AnalysisType.TREND_ANALYSIS,
            insights=insights,
            summary=f"Trend analysis examined {len(trends)} metrics with {len(insights)} concerning trends",
            key_findings=[insight.title for insight in insights],
            performance_score=performance_score,
            trend_analysis=trends,
            anomalies=[],
            correlations=[],
            recommendations=[rec for insight in insights for rec in insight.recommendations],
            confidence_score=0.7
        )
    
    async def _generic_analysis(
        self,
        execution_results: Dict[str, Any],
        expert_expectations: Dict[str, Any]
    ) -> AnalysisResult:
        """Perform generic analysis when specific analysis is not available"""
        insights = []
        
        # Basic metric analysis
        metrics = execution_results.get('metrics', {})
        
        for metric, value in metrics.items():
            if metric in self.performance_benchmarks:
                benchmark = self.performance_benchmarks[metric]
                if value > benchmark['poor']:
                    insights.append(Insight(
                        insight_id=f"generic_{metric}_{int(time.time())}",
                        category="generic",
                        level=InsightLevel.NOTABLE,
                        title=f"Poor {metric.replace('_', ' ').title()} Performance",
                        description=f"{metric.replace('_', ' ').title()} value of {value} exceeds poor threshold",
                        evidence=[f"{metric}: {value}", f"Poor threshold: {benchmark['poor']}"],
                        implications=["Performance concerns", "May impact user experience"],
                        recommendations=["Investigate and optimize", "Monitor closely"],
                        confidence=0.6,
                        affected_metrics=[metric]
                    ))
        
        performance_score = 0.7  # Default generic score
        
        return AnalysisResult(
            analysis_type=AnalysisType.PERFORMANCE_ANALYSIS,
            insights=insights,
            summary=f"Generic analysis found {len(insights)} areas for attention",
            key_findings=[insight.title for insight in insights],
            performance_score=performance_score,
            trend_analysis={},
            anomalies=[],
            correlations=[],
            recommendations=[rec for insight in insights for rec in insight.recommendations],
            confidence_score=0.6
        )
    
    async def _perform_correlation_analysis(self, execution_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Perform correlation analysis between metrics"""
        correlations = []
        metrics = execution_results.get('metrics', {})
        time_series = execution_results.get('time_series', {})
        
        for rule in self.correlation_rules:
            metric1, metric2 = rule['metrics']
            
            if metric1 in time_series and metric2 in time_series:
                values1 = time_series[metric1]
                values2 = time_series[metric2]
                
                if len(values1) == len(values2) and len(values1) >= 5:
                    correlation = self._calculate_correlation(values1, values2)
                    
                    if abs(correlation) >= rule['threshold']:
                        correlations.append({
                            'metric1': metric1,
                            'metric2': metric2,
                            'correlation': correlation,
                            'strength': 'strong' if abs(correlation) > 0.8 else 'moderate',
                            'interpretation': rule['interpretation'],
                            'confidence': 0.8
                        })
        
        return correlations
    
    async def _detect_anomalies(self, execution_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies in metrics"""
        anomalies = []
        time_series = execution_results.get('time_series', {})
        
        for metric, values in time_series.items():
            if len(values) >= 10 and metric in self.anomaly_thresholds:
                threshold_config = self.anomaly_thresholds[metric]
                
                mean_value = statistics.mean(values)
                std_dev = statistics.stdev(values) if len(values) > 1 else 0
                
                for i, value in enumerate(values):
                    deviation = abs(value - mean_value)
                    threshold = max(
                        std_dev * threshold_config['deviation_multiplier'],
                        threshold_config['min_threshold']
                    )
                    
                    if deviation > threshold:
                        anomalies.append({
                            'metric': metric,
                            'value': value,
                            'timestamp_index': i,
                            'deviation': deviation,
                            'severity': 'high' if deviation > threshold * 1.5 else 'medium',
                            'description': f"Anomalous {metric} value: {value} (deviation: {deviation:.2f})"
                        })
        
        return anomalies
    
    async def _perform_trend_analysis(
        self,
        execution_results: Dict[str, Any],
        historical_patterns: Dict[str, Any]
    ) -> Dict[str, TrendDirection]:
        """Perform detailed trend analysis"""
        trends = {}
        time_series = execution_results.get('time_series', {})
        
        for metric, values in time_series.items():
            if len(values) >= 5:
                trends[metric] = self._calculate_trend_direction(values)
        
        return trends
    
    def _calculate_trend_direction(self, values: List[float]) -> TrendDirection:
        """Calculate trend direction from time series values"""
        if len(values) < 3:
            return TrendDirection.STABLE
        
        # Calculate linear trend
        n = len(values)
        x_values = list(range(n))
        
        # Linear regression slope
        x_mean = statistics.mean(x_values)
        y_mean = statistics.mean(values)
        
        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, values))
        denominator = sum((x - x_mean) ** 2 for x in x_values)
        
        if denominator == 0:
            return TrendDirection.STABLE
        
        slope = numerator / denominator
        
        # Calculate relative slope (as percentage of mean)
        if y_mean != 0:
            relative_slope = slope / y_mean
        else:
            relative_slope = slope
        
        # Classify trend
        if relative_slope > 0.05:  # 5% increase per time unit
            return TrendDirection.IMPROVING if 'error' not in values.__class__.__name__.lower() else TrendDirection.DEGRADING
        elif relative_slope < -0.05:  # 5% decrease per time unit
            return TrendDirection.DEGRADING if 'error' not in values.__class__.__name__.lower() else TrendDirection.IMPROVING
        else:
            # Check for volatility
            variance = statistics.variance(values) if len(values) > 1 else 0
            cv = (variance ** 0.5) / y_mean if y_mean != 0 else 0
            
            if cv > 0.3:  # High coefficient of variation
                return TrendDirection.VOLATILE
            else:
                return TrendDirection.STABLE
    
    def _calculate_correlation(self, values1: List[float], values2: List[float]) -> float:
        """Calculate Pearson correlation coefficient"""
        if len(values1) != len(values2) or len(values1) < 2:
            return 0.0
        
        mean1 = statistics.mean(values1)
        mean2 = statistics.mean(values2)
        
        numerator = sum((x - mean1) * (y - mean2) for x, y in zip(values1, values2))
        
        sum_sq1 = sum((x - mean1) ** 2 for x in values1)
        sum_sq2 = sum((y - mean2) ** 2 for y in values2)
        
        denominator = (sum_sq1 * sum_sq2) ** 0.5
        
        if denominator == 0:
            return 0.0
        
        return numerator / denominator
    
    async def _generate_final_insights(
        self,
        all_insights: List[Insight],
        correlations: List[Dict[str, Any]],
        anomalies: List[Dict[str, Any]],
        trend_analysis: Dict[str, TrendDirection]
    ) -> List[Insight]:
        """Generate final consolidated insights"""
        
        # Start with existing insights
        final_insights = all_insights.copy()
        
        # Add correlation insights
        for correlation in correlations:
            if correlation['strength'] == 'strong':
                final_insights.append(Insight(
                    insight_id=f"corr_{int(time.time())}_{len(final_insights)}",
                    category="correlation",
                    level=InsightLevel.NOTABLE,
                    title=f"Strong Correlation: {correlation['metric1']} and {correlation['metric2']}",
                    description=correlation['interpretation'],
                    evidence=[f"Correlation: {correlation['correlation']:.2f}"],
                    implications=["Interdependent metrics", "Potential causal relationship"],
                    recommendations=["Monitor both metrics together", "Consider joint optimization"],
                    confidence=correlation['confidence'],
                    affected_metrics=[correlation['metric1'], correlation['metric2']]
                ))
        
        # Add anomaly insights
        high_severity_anomalies = [a for a in anomalies if a['severity'] == 'high']
        if len(high_severity_anomalies) > 3:
            final_insights.append(Insight(
                insight_id=f"anom_{int(time.time())}",
                category="anomaly",
                level=InsightLevel.IMPORTANT,
                title="Multiple High-Severity Anomalies Detected",
                description=f"Detected {len(high_severity_anomalies)} high-severity anomalies",
                evidence=[f"High-severity anomalies: {len(high_severity_anomalies)}"],
                implications=["System instability", "Unpredictable behavior", "Data quality issues"],
                recommendations=["Investigate anomaly patterns", "Improve monitoring", "Add alerting"],
                confidence=0.8,
                affected_metrics=list(set(a['metric'] for a in high_severity_anomalies))
            ))
        
        # Sort insights by importance
        final_insights.sort(key=lambda x: (
            x.level == InsightLevel.CRITICAL,
            x.level == InsightLevel.IMPORTANT,
            x.confidence
        ), reverse=True)
        
        return final_insights
    
    def _calculate_overall_performance_score(self, execution_results: Dict[str, Any]) -> float:
        """Calculate overall performance score"""
        metrics = execution_results.get('metrics', {})
        scores = []
        
        # Individual metric scores
        for metric, value in metrics.items():
            if metric in self.performance_benchmarks:
                score = self._calculate_metric_score(metric, value)
                scores.append(score)
        
        if scores:
            return statistics.mean(scores)
        else:
            return 0.5  # Default neutral score
    
    def _calculate_metric_score(self, metric: str, value: float) -> float:
        """Calculate score for individual metric"""
        benchmarks = self.performance_benchmarks[metric]
        
        # For metrics where lower is better (response_time, error_rate, resource usage)
        if metric in ['response_time', 'error_rate', 'cpu_utilization', 'memory_usage']:
            if value <= benchmarks['excellent']:
                return 1.0
            elif value <= benchmarks['good']:
                return 0.8
            elif value <= benchmarks['fair']:
                return 0.6
            elif value <= benchmarks['poor']:
                return 0.4
            else:
                return 0.2
        else:
            # For metrics where higher is better (throughput)
            if value >= benchmarks['excellent']:
                return 1.0
            elif value >= benchmarks['good']:
                return 0.8
            elif value >= benchmarks['fair']:
                return 0.6
            elif value >= benchmarks['poor']:
                return 0.4
            else:
                return 0.2
    
    def _calculate_performance_score(self, metrics: Dict[str, Any]) -> float:
        """Calculate performance-specific score"""
        scores = []
        
        # Response time score
        response_time = metrics.get('response_time', 500)
        scores.append(self._calculate_metric_score('response_time', response_time))
        
        # Throughput score
        throughput = metrics.get('throughput', 100)
        scores.append(self._calculate_metric_score('throughput', throughput))
        
        # Resource usage scores
        cpu_usage = metrics.get('cpu_utilization', 50)
        scores.append(self._calculate_metric_score('cpu_utilization', cpu_usage))
        
        memory_usage = metrics.get('memory_usage', 50)
        scores.append(self._calculate_metric_score('memory_usage', memory_usage))
        
        return statistics.mean(scores) if scores else 0.5
    
    def _calculate_reliability_score(self, metrics: Dict[str, Any]) -> float:
        """Calculate reliability-specific score"""
        scores = []
        
        # Error rate score
        error_rate = metrics.get('error_rate', 0.01)
        scores.append(self._calculate_metric_score('error_rate', error_rate))
        
        # Uptime score
        uptime = metrics.get('uptime', 0.99)
        scores.append(uptime)  # Uptime is already 0-1
        
        # Recovery time score (inverted - lower is better)
        recovery_time = metrics.get('recovery_time', 60)
        if recovery_time <= 30:
            scores.append(1.0)
        elif recovery_time <= 60:
            scores.append(0.8)
        elif recovery_time <= 300:
            scores.append(0.6)
        else:
            scores.append(0.4)
        
        return statistics.mean(scores) if scores else 0.5
    
    def _calculate_scalability_score(self, metrics: Dict[str, Any], scaling_events: List[Dict[str, Any]]) -> float:
        """Calculate scalability-specific score"""
        scores = []
        
        # Scaling efficiency score
        if scaling_events:
            avg_scale_time = statistics.mean([event.get('scale_time', 60) for event in scaling_events])
            if avg_scale_time <= 30:
                scores.append(1.0)
            elif avg_scale_time <= 60:
                scores.append(0.8)
            elif avg_scale_time <= 120:
                scores.append(0.6)
            else:
                scores.append(0.4)
        
        # Capacity score
        max_load = metrics.get('max_load_handled', 1000)
        if max_load >= 10000:
            scores.append(1.0)
        elif max_load >= 5000:
            scores.append(0.8)
        elif max_load >= 1000:
            scores.append(0.6)
        else:
            scores.append(0.4)
        
        return statistics.mean(scores) if scores else 0.5
    
    def _calculate_security_score(self, security_metrics: Dict[str, Any]) -> float:
        """Calculate security-specific score"""
        scores = []
        
        # Security incidents score
        incidents = security_metrics.get('security_incidents', 0)
        if incidents == 0:
            scores.append(1.0)
        elif incidents <= 2:
            scores.append(0.6)
        else:
            scores.append(0.2)
        
        # Authentication failure rate score
        auth_failures = security_metrics.get('authentication_failures', 0)
        total_requests = security_metrics.get('total_requests', 1)
        failure_rate = auth_failures / total_requests
        
        if failure_rate <= 0.01:
            scores.append(1.0)
        elif failure_rate <= 0.05:
            scores.append(0.6)
        else:
            scores.append(0.2)
        
        return statistics.mean(scores) if scores else 0.5
    
    def _calculate_chaos_score(self, chaos_experiments: List[Dict[str, Any]]) -> float:
        """Calculate chaos engineering score"""
        if not chaos_experiments:
            return 0.5
        
        scores = []
        
        # Recovery success rate
        successful_recoveries = sum(1 for exp in chaos_experiments if exp.get('recovery_successful', False))
        success_rate = successful_recoveries / len(chaos_experiments)
        scores.append(success_rate)
        
        # Recovery time score
        recovery_times = [exp.get('recovery_time', 60) for exp in chaos_experiments]
        avg_recovery_time = statistics.mean(recovery_times)
        
        if avg_recovery_time <= 30:
            scores.append(1.0)
        elif avg_recovery_time <= 60:
            scores.append(0.8)
        elif avg_recovery_time <= 120:
            scores.append(0.6)
        else:
            scores.append(0.4)
        
        return statistics.mean(scores)
    
    def _generate_analysis_summary(self, insights: List[Insight], performance_score: float) -> str:
        """Generate analysis summary"""
        critical_count = sum(1 for i in insights if i.level == InsightLevel.CRITICAL)
        important_count = sum(1 for i in insights if i.level == InsightLevel.IMPORTANT)
        
        if critical_count > 0:
            summary = f"Analysis identified {critical_count} critical issues requiring immediate attention. "
        elif important_count > 0:
            summary = f"Analysis found {important_count} important areas for improvement. "
        else:
            summary = "Analysis shows generally stable system performance. "
        
        summary += f"Overall performance score: {performance_score:.1f}/1.0. "
        
        if performance_score >= 0.8:
            summary += "System performance is excellent."
        elif performance_score >= 0.6:
            summary += "System performance is good with room for optimization."
        elif performance_score >= 0.4:
            summary += "System performance needs improvement."
        else:
            summary += "System performance requires significant attention."
        
        return summary
    
    def _extract_key_findings(self, insights: List[Insight]) -> List[str]:
        """Extract key findings from insights"""
        key_findings = []
        
        # Add critical and important insights as key findings
        for insight in insights:
            if insight.level in [InsightLevel.CRITICAL, InsightLevel.IMPORTANT]:
                key_findings.append(insight.title)
        
        return key_findings[:10]  # Limit to top 10
    
    def _generate_recommendations(self, insights: List[Insight], context: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Collect all recommendations from insights
        for insight in insights:
            recommendations.extend(insight.recommendations)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        # Prioritize based on insight levels
        critical_recs = []
        important_recs = []
        other_recs = []
        
        for insight in insights:
            for rec in insight.recommendations:
                if insight.level == InsightLevel.CRITICAL:
                    critical_recs.extend(insight.recommendations)
                elif insight.level == InsightLevel.IMPORTANT:
                    important_recs.extend(insight.recommendations)
                else:
                    other_recs.extend(insight.recommendations)
        
        # Combine prioritized recommendations
        prioritized = critical_recs + important_recs + other_recs
        
        # Remove duplicates and limit
        final_recommendations = []
        seen = set()
        for rec in prioritized:
            if rec not in seen and len(final_recommendations) < 15:
                seen.add(rec)
                final_recommendations.append(rec)
        
        return final_recommendations
    
    def _calculate_analysis_confidence(self, insights: List[Insight], execution_results: Dict[str, Any]) -> float:
        """Calculate confidence in analysis results"""
        confidence_factors = []
        
        # Data quality factor
        data_quality = self._assess_data_quality(execution_results)
        confidence_factors.append(data_quality)
        
        # Insight confidence factor
        if insights:
            avg_insight_confidence = statistics.mean([i.confidence for i in insights])
            confidence_factors.append(avg_insight_confidence)
        
        # Data completeness factor
        expected_metrics = ['response_time', 'throughput', 'error_rate', 'cpu_utilization', 'memory_usage']
        available_metrics = execution_results.get('metrics', {}).keys()
        completeness = len(set(expected_metrics) & set(available_metrics)) / len(expected_metrics)
        confidence_factors.append(completeness)
        
        return statistics.mean(confidence_factors) if confidence_factors else 0.5
    
    def _assess_data_quality(self, execution_results: Dict[str, Any]) -> float:
        """Assess quality of input data"""
        quality_score = 0.5
        
        # Check for required data sections
        if 'metrics' in execution_results:
            quality_score += 0.2
        
        if 'time_series' in execution_results:
            quality_score += 0.2
        
        # Check data completeness
        metrics = execution_results.get('metrics', {})
        if len(metrics) >= 5:
            quality_score += 0.1
        
        return min(1.0, quality_score)
    
    def _has_time_series_data(self, execution_results: Dict[str, Any]) -> bool:
        """Check if time series data is available"""
        time_series = execution_results.get('time_series', {})
        return len(time_series) > 0 and any(len(values) >= 5 for values in time_series.values())
    
    def _insight_to_dict(self, insight: Insight) -> Dict[str, Any]:
        """Convert insight to dictionary"""
        return {
            'insight_id': insight.insight_id,
            'category': insight.category,
            'level': insight.level.value,
            'title': insight.title,
            'description': insight.description,
            'evidence': insight.evidence,
            'implications': insight.implications,
            'recommendations': insight.recommendations,
            'confidence': insight.confidence,
            'affected_metrics': insight.affected_metrics,
            'trend_direction': insight.trend_direction.value if insight.trend_direction else None
        }
    
    def _store_analysis(
        self,
        analysis: Dict[str, Any],
        execution_results: Dict[str, Any],
        context: Dict[str, Any]
    ):
        """Store analysis results for learning"""
        record = {
            'timestamp': time.time(),
            'performance_score': analysis['performance_score'],
            'insight_count': len(analysis['insights']),
            'critical_insights': analysis['analysis_metadata']['critical_insights'],
            'confidence_score': analysis['confidence_score'],
            'data_quality_score': analysis['analysis_metadata']['data_quality_score'],
            'analysis_types': analysis['analysis_metadata']['analysis_types']
        }
        
        self.analysis_history.append(record)
        
        # Keep only last 100 records
        if len(self.analysis_history) > 100:
            self.analysis_history = self.analysis_history[-100:]
    
    def _generate_fallback_analysis(self) -> Dict[str, Any]:
        """Generate fallback analysis when main analysis fails"""
        return {
            'insights': [],
            'summary': 'Analysis failed - using fallback basic assessment',
            'key_findings': ['Analysis engine encountered an error'],
            'performance_score': 0.5,
            'trend_analysis': {},
            'anomalies': [],
            'correlations': [],
            'recommendations': ['Review system logs', 'Check data quality', 'Retry analysis'],
            'confidence_score': 0.3,
            'analysis_metadata': {
                'timestamp': time.time(),
                'analysis_types': ['fallback'],
                'total_insights': 0,
                'critical_insights': 0,
                'data_quality_score': 0.3
            }
        }
    
    # Specific pattern detection methods
    
    def _check_response_time_trend(self, metrics: Dict[str, Any]) -> bool:
        """Check for response time degradation pattern"""
        time_series = metrics.get('time_series', {})
        response_times = time_series.get('response_time', [])
        
        if len(response_times) >= 5:
            trend = self._calculate_trend_direction(response_times)
            return trend == TrendDirection.DEGRADING
        
        return False
    
    def _check_throughput_decline(self, metrics: Dict[str, Any]) -> bool:
        """Check for throughput decline pattern"""
        time_series = metrics.get('time_series', {})
        throughput_values = time_series.get('throughput', [])
        
        if len(throughput_values) >= 5:
            trend = self._calculate_trend_direction(throughput_values)
            return trend == TrendDirection.DEGRADING
        
        return False
    
    def _detect_memory_leak(self, metrics: Dict[str, Any]) -> bool:
        """Detect memory leak pattern"""
        time_series = metrics.get('time_series', {})
        memory_values = time_series.get('memory_usage', [])
        
        if len(memory_values) >= 10:
            # Check for consistent upward trend
            recent_values = memory_values[-5:]
            earlier_values = memory_values[-10:-5]
            
            recent_avg = statistics.mean(recent_values)
            earlier_avg = statistics.mean(earlier_values)
            
            # Memory leak if recent average is significantly higher
            return recent_avg > earlier_avg * 1.1 and recent_avg > 80
        
        return False
    
    def _detect_cpu_saturation(self, metrics: Dict[str, Any]) -> bool:
        """Detect CPU saturation pattern"""
        time_series = metrics.get('time_series', {})
        cpu_values = time_series.get('cpu_utilization', [])
        
        if len(cpu_values) >= 5:
            # Check for sustained high CPU
            high_cpu_count = sum(1 for val in cpu_values[-5:] if val > 90)
            return high_cpu_count >= 3  # 3 out of 5 recent values
        
        return False
    
    def _detect_error_spike(self, metrics: Dict[str, Any]) -> bool:
        """Detect error rate spike pattern"""
        time_series = metrics.get('time_series', {})
        error_values = time_series.get('error_rate', [])
        
        if len(error_values) >= 5:
            recent_max = max(error_values[-5:])
            overall_avg = statistics.mean(error_values)
            
            # Error spike if recent max is significantly higher than average
            return recent_max > overall_avg * 3 and recent_max > 0.05
        
        return False
    
    # Public interface methods
    
    def get_analysis_history(self) -> List[Dict[str, Any]]:
        """Get analysis history"""
        return self.analysis_history.copy()
    
    def get_performance_benchmarks(self) -> Dict[str, Dict[str, float]]:
        """Get performance benchmarks"""
        return self.performance_benchmarks.copy()
    
    def update_performance_benchmarks(self, updates: Dict[str, Dict[str, float]]):
        """Update performance benchmarks"""
        for metric, benchmarks in updates.items():
            if metric in self.performance_benchmarks:
                self.performance_benchmarks[metric].update(benchmarks)
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics"""
        if not self.analysis_history:
            return {'no_data': True}
        
        scores = [record['performance_score'] for record in self.analysis_history]
        confidences = [record['confidence_score'] for record in self.analysis_history]
        
        return {
            'total_analyses': len(self.analysis_history),
            'average_performance_score': statistics.mean(scores),
            'average_confidence': statistics.mean(confidences),
            'score_trend': 'improving' if len(scores) > 5 and scores[-5:] > scores[-10:-5] else 'stable',
            'recent_performance': {
                'last_5_avg_score': statistics.mean(scores[-5:]) if len(scores) >= 5 else statistics.mean(scores),
                'last_5_avg_confidence': statistics.mean(confidences[-5:]) if len(confidences) >= 5 else statistics.mean(confidences)
            }
        }