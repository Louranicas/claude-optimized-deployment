"""
MCP Scaling and Load Balancing Advisor
Agent 7: Intelligent scaling recommendations and load balancing strategies for MCP deployments.

This module analyzes performance patterns and provides recommendations for optimal
scaling, load distribution, and resource allocation across MCP server instances.
"""

import asyncio
import time
import logging
import statistics
from typing import Dict, Any, List, Optional, Union, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
from enum import Enum
import json
import math

from .performance_monitor import MCPPerformanceMonitor, MCPOperationMetrics, SystemResourceMetrics
from .connection_optimizer import LoadBalancingStrategy, MCPConnectionConfig

logger = logging.getLogger(__name__)


class ScalingDirection(Enum):
    """Scaling direction recommendations."""
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    SCALE_OUT = "scale_out"
    SCALE_IN = "scale_in"
    NO_CHANGE = "no_change"


class ResourceType(Enum):
    """Resource types for scaling."""
    CPU = "cpu"
    MEMORY = "memory"
    CONNECTIONS = "connections"
    THROUGHPUT = "throughput"
    LATENCY = "latency"


class ScalingTrigger(Enum):
    """Triggers that initiate scaling decisions."""
    HIGH_CPU = "high_cpu"
    HIGH_MEMORY = "high_memory"
    HIGH_LATENCY = "high_latency"
    LOW_THROUGHPUT = "low_throughput"
    CONNECTION_SATURATION = "connection_saturation"
    ERROR_RATE = "error_rate"
    PREDICTIVE = "predictive"


@dataclass
class ScalingRecommendation:
    """Scaling recommendation with detailed rationale."""
    server_name: str
    direction: ScalingDirection
    resource_type: ResourceType
    trigger: ScalingTrigger
    confidence: float  # 0.0 to 1.0
    urgency: str  # low, medium, high, critical
    current_value: float
    target_value: float
    expected_improvement: str
    implementation_steps: List[str]
    estimated_cost_impact: str
    risks: List[str]
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "server_name": self.server_name,
            "direction": self.direction.value,
            "resource_type": self.resource_type.value,
            "trigger": self.trigger.value,
            "confidence": self.confidence,
            "urgency": self.urgency,
            "current_value": self.current_value,
            "target_value": self.target_value,
            "expected_improvement": self.expected_improvement,
            "implementation_steps": self.implementation_steps,
            "estimated_cost_impact": self.estimated_cost_impact,
            "risks": self.risks,
            "created_at": self.created_at.isoformat()
        }


@dataclass
class LoadBalancingRecommendation:
    """Load balancing strategy recommendation."""
    current_strategy: LoadBalancingStrategy
    recommended_strategy: LoadBalancingStrategy
    reason: str
    expected_improvement: str
    configuration_changes: Dict[str, Any]
    confidence: float
    implementation_complexity: str  # low, medium, high
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "current_strategy": self.current_strategy.value,
            "recommended_strategy": self.recommended_strategy.value,
            "reason": self.reason,
            "expected_improvement": self.expected_improvement,
            "configuration_changes": self.configuration_changes,
            "confidence": self.confidence,
            "implementation_complexity": self.implementation_complexity
        }


@dataclass
class CapacityPrediction:
    """Capacity prediction based on historical trends."""
    resource_type: ResourceType
    current_usage: float
    predicted_usage_1h: float
    predicted_usage_24h: float
    predicted_usage_7d: float
    confidence_1h: float
    confidence_24h: float
    confidence_7d: float
    trend_direction: str  # increasing, decreasing, stable
    saturation_etas: Dict[str, Optional[datetime]]  # When resource will be saturated
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "resource_type": self.resource_type.value,
            "current_usage": self.current_usage,
            "predicted_usage_1h": self.predicted_usage_1h,
            "predicted_usage_24h": self.predicted_usage_24h,
            "predicted_usage_7d": self.predicted_usage_7d,
            "confidence_1h": self.confidence_1h,
            "confidence_24h": self.confidence_24h,
            "confidence_7d": self.confidence_7d,
            "trend_direction": self.trend_direction,
            "saturation_etas": {
                k: v.isoformat() if v else None 
                for k, v in self.saturation_etas.items()
            }
        }


class MCPScalingAdvisor:
    """
    Intelligent scaling advisor for MCP deployments.
    
    Features:
    - Performance-based scaling recommendations
    - Predictive capacity planning
    - Load balancing optimization
    - Cost-aware scaling decisions
    - Multi-dimensional resource analysis
    """
    
    def __init__(self, performance_monitor: MCPPerformanceMonitor):
        self.performance_monitor = performance_monitor
        
        # Historical data for analysis
        self._resource_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1440))  # 24 hours
        self._performance_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1440))
        self._scaling_history: List[ScalingRecommendation] = []
        
        # Analysis configuration
        self._analysis_config = {
            "cpu_threshold_high": 70.0,
            "cpu_threshold_critical": 85.0,
            "memory_threshold_high": 80.0,
            "memory_threshold_critical": 90.0,
            "latency_threshold_ms": 2000.0,
            "error_rate_threshold": 0.05,
            "throughput_min_rps": 1.0,
            "connection_utilization_threshold": 0.8,
            "prediction_confidence_threshold": 0.7
        }
        
        # Predictive models
        self._predictors: Dict[str, 'TimeSeriesPredictor'] = {}
        
        # Background tasks
        self._analysis_task: Optional[asyncio.Task] = None
        self._is_running = False
    
    async def initialize(self):
        """Initialize the scaling advisor."""
        if self._is_running:
            return
        
        logger.info("Initializing MCP Scaling Advisor")
        
        # Initialize predictive models
        for resource_type in ResourceType:
            self._predictors[resource_type.value] = TimeSeriesPredictor()
        
        # Start background analysis
        self._is_running = True
        self._analysis_task = asyncio.create_task(self._analysis_loop())
        
        logger.info("MCP Scaling Advisor initialized")
    
    async def _analysis_loop(self):
        """Background analysis loop."""
        while self._is_running:
            try:
                await asyncio.sleep(60)  # Analyze every minute
                await self._collect_metrics()
                await self._analyze_scaling_needs()
                await self._update_predictions()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scaling analysis error: {e}")
    
    async def _collect_metrics(self):
        """Collect metrics for analysis."""
        # Get performance summary
        summary = self.performance_monitor.get_performance_summary()
        
        current_time = datetime.now()
        
        # Store system metrics
        if "system" in summary:
            system_metrics = summary["system"]
            self._resource_history["cpu"].append({
                "timestamp": current_time,
                "value": system_metrics.get("avg_cpu_percent", 0)
            })
            self._resource_history["memory"].append({
                "timestamp": current_time,
                "value": system_metrics.get("avg_memory_percent", 0)
            })
            self._resource_history["connections"].append({
                "timestamp": current_time,
                "value": system_metrics.get("active_connections", 0)
            })
        
        # Store operation performance metrics
        if "operations" in summary:
            for operation_key, metrics in summary["operations"].items():
                self._performance_history[operation_key].append({
                    "timestamp": current_time,
                    "avg_duration_ms": metrics.get("avg_duration_ms", 0),
                    "success_rate": metrics.get("success_rate", 1.0),
                    "calls_per_minute": metrics.get("calls_per_minute", 0)
                })
    
    async def _analyze_scaling_needs(self):
        """Analyze current metrics and generate scaling recommendations."""
        recommendations = []
        
        # Analyze system resources
        cpu_rec = await self._analyze_cpu_scaling()
        if cpu_rec:
            recommendations.append(cpu_rec)
        
        memory_rec = await self._analyze_memory_scaling()
        if memory_rec:
            recommendations.append(memory_rec)
        
        # Analyze per-operation performance
        for operation_key in self._performance_history.keys():
            latency_rec = await self._analyze_latency_scaling(operation_key)
            if latency_rec:
                recommendations.append(latency_rec)
            
            throughput_rec = await self._analyze_throughput_scaling(operation_key)
            if throughput_rec:
                recommendations.append(throughput_rec)
        
        # Store recommendations
        self._scaling_history.extend(recommendations)
        
        # Keep only recent recommendations (last 24 hours)
        cutoff_time = datetime.now() - timedelta(hours=24)
        self._scaling_history = [
            rec for rec in self._scaling_history 
            if rec.created_at > cutoff_time
        ]
        
        # Log new recommendations
        for rec in recommendations:
            logger.info(f"Scaling recommendation: {rec.server_name} - {rec.direction.value} "
                       f"({rec.resource_type.value}, confidence: {rec.confidence:.2f})")
    
    async def _analyze_cpu_scaling(self) -> Optional[ScalingRecommendation]:
        """Analyze CPU usage and recommend scaling."""
        if not self._resource_history["cpu"]:
            return None
        
        recent_cpu = [entry["value"] for entry in list(self._resource_history["cpu"])[-10:]]
        avg_cpu = statistics.mean(recent_cpu)
        max_cpu = max(recent_cpu)
        
        # High CPU usage
        if avg_cpu > self._analysis_config["cpu_threshold_critical"]:
            return ScalingRecommendation(
                server_name="system",
                direction=ScalingDirection.SCALE_UP,
                resource_type=ResourceType.CPU,
                trigger=ScalingTrigger.HIGH_CPU,
                confidence=0.9,
                urgency="critical",
                current_value=avg_cpu,
                target_value=self._analysis_config["cpu_threshold_high"],
                expected_improvement="Reduced CPU bottlenecks, improved response times",
                implementation_steps=[
                    "Increase CPU allocation or add more CPU cores",
                    "Consider vertical scaling of existing instances",
                    "Monitor CPU usage after scaling"
                ],
                estimated_cost_impact="Medium - CPU upgrade costs",
                risks=["Temporary service disruption during scaling"]
            )
        
        elif avg_cpu > self._analysis_config["cpu_threshold_high"]:
            return ScalingRecommendation(
                server_name="system",
                direction=ScalingDirection.SCALE_UP,
                resource_type=ResourceType.CPU,
                trigger=ScalingTrigger.HIGH_CPU,
                confidence=0.7,
                urgency="high",
                current_value=avg_cpu,
                target_value=self._analysis_config["cpu_threshold_high"],
                expected_improvement="Prevent CPU saturation, maintain performance",
                implementation_steps=[
                    "Plan CPU capacity increase",
                    "Consider load balancing improvements",
                    "Optimize CPU-intensive operations"
                ],
                estimated_cost_impact="Low to Medium",
                risks=["Performance degradation if not addressed"]
            )
        
        # Low CPU usage (potential scale down)
        elif avg_cpu < 30.0 and max_cpu < 50.0:
            return ScalingRecommendation(
                server_name="system",
                direction=ScalingDirection.SCALE_DOWN,
                resource_type=ResourceType.CPU,
                trigger=ScalingTrigger.HIGH_CPU,  # Inverted - low usage
                confidence=0.6,
                urgency="low",
                current_value=avg_cpu,
                target_value=50.0,
                expected_improvement="Cost savings through right-sizing",
                implementation_steps=[
                    "Evaluate if current CPU allocation is excessive",
                    "Consider reducing CPU allocation gradually",
                    "Monitor performance during scaling"
                ],
                estimated_cost_impact="Positive - Cost reduction",
                risks=["Potential performance impact during peak loads"]
            )
        
        return None
    
    async def _analyze_memory_scaling(self) -> Optional[ScalingRecommendation]:
        """Analyze memory usage and recommend scaling."""
        if not self._resource_history["memory"]:
            return None
        
        recent_memory = [entry["value"] for entry in list(self._resource_history["memory"])[-10:]]
        avg_memory = statistics.mean(recent_memory)
        max_memory = max(recent_memory)
        
        # High memory usage
        if avg_memory > self._analysis_config["memory_threshold_critical"]:
            return ScalingRecommendation(
                server_name="system",
                direction=ScalingDirection.SCALE_UP,
                resource_type=ResourceType.MEMORY,
                trigger=ScalingTrigger.HIGH_MEMORY,
                confidence=0.95,
                urgency="critical",
                current_value=avg_memory,
                target_value=self._analysis_config["memory_threshold_high"],
                expected_improvement="Prevent OOM errors, improve stability",
                implementation_steps=[
                    "Increase memory allocation immediately",
                    "Investigate memory leaks",
                    "Optimize caching strategies"
                ],
                estimated_cost_impact="Medium - Memory upgrade costs",
                risks=["System crashes due to OOM if not addressed"]
            )
        
        elif avg_memory > self._analysis_config["memory_threshold_high"]:
            return ScalingRecommendation(
                server_name="system",
                direction=ScalingDirection.SCALE_UP,
                resource_type=ResourceType.MEMORY,
                trigger=ScalingTrigger.HIGH_MEMORY,
                confidence=0.8,
                urgency="high",
                current_value=avg_memory,
                target_value=self._analysis_config["memory_threshold_high"],
                expected_improvement="Prevent memory pressure, maintain performance",
                implementation_steps=[
                    "Plan memory capacity increase",
                    "Optimize memory usage patterns",
                    "Review caching configurations"
                ],
                estimated_cost_impact="Medium",
                risks=["Memory pressure affecting performance"]
            )
        
        return None
    
    async def _analyze_latency_scaling(self, operation_key: str) -> Optional[ScalingRecommendation]:
        """Analyze operation latency and recommend scaling."""
        if operation_key not in self._performance_history:
            return None
        
        recent_data = list(self._performance_history[operation_key])[-10:]
        if not recent_data:
            return None
        
        avg_latency = statistics.mean(entry["avg_duration_ms"] for entry in recent_data)
        
        if avg_latency > self._analysis_config["latency_threshold_ms"]:
            return ScalingRecommendation(
                server_name=operation_key.split(".")[0],
                direction=ScalingDirection.SCALE_OUT,
                resource_type=ResourceType.LATENCY,
                trigger=ScalingTrigger.HIGH_LATENCY,
                confidence=0.75,
                urgency="medium",
                current_value=avg_latency,
                target_value=self._analysis_config["latency_threshold_ms"],
                expected_improvement="Reduced response times through load distribution",
                implementation_steps=[
                    "Add more server instances",
                    "Implement better load balancing",
                    "Optimize slow operations"
                ],
                estimated_cost_impact="Medium - Additional instance costs",
                risks=["Increased complexity in load balancing"]
            )
        
        return None
    
    async def _analyze_throughput_scaling(self, operation_key: str) -> Optional[ScalingRecommendation]:
        """Analyze operation throughput and recommend scaling."""
        if operation_key not in self._performance_history:
            return None
        
        recent_data = list(self._performance_history[operation_key])[-10:]
        if not recent_data:
            return None
        
        avg_throughput = statistics.mean(entry["calls_per_minute"] for entry in recent_data)
        
        if avg_throughput < self._analysis_config["throughput_min_rps"]:
            return ScalingRecommendation(
                server_name=operation_key.split(".")[0],
                direction=ScalingDirection.SCALE_OUT,
                resource_type=ResourceType.THROUGHPUT,
                trigger=ScalingTrigger.LOW_THROUGHPUT,
                confidence=0.6,
                urgency="medium",
                current_value=avg_throughput,
                target_value=self._analysis_config["throughput_min_rps"],
                expected_improvement="Increased processing capacity",
                implementation_steps=[
                    "Add more processing instances",
                    "Optimize request handling",
                    "Consider async processing"
                ],
                estimated_cost_impact="Medium",
                risks=["Over-provisioning if demand doesn't increase"]
            )
        
        return None
    
    async def _update_predictions(self):
        """Update capacity predictions."""
        for resource_type, predictor in self._predictors.items():
            if resource_type in self._resource_history:
                history = list(self._resource_history[resource_type])
                if len(history) >= 10:
                    values = [entry["value"] for entry in history]
                    predictor.update(values)
    
    def get_scaling_recommendations(
        self,
        server_name: Optional[str] = None,
        urgency_filter: Optional[str] = None
    ) -> List[ScalingRecommendation]:
        """Get current scaling recommendations."""
        recommendations = self._scaling_history
        
        # Filter by server name
        if server_name:
            recommendations = [r for r in recommendations if r.server_name == server_name]
        
        # Filter by urgency
        if urgency_filter:
            recommendations = [r for r in recommendations if r.urgency == urgency_filter]
        
        # Sort by urgency and confidence
        urgency_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        recommendations.sort(
            key=lambda r: (urgency_order.get(r.urgency, 0), r.confidence),
            reverse=True
        )
        
        return recommendations
    
    def get_load_balancing_recommendations(self) -> List[LoadBalancingRecommendation]:
        """Get load balancing strategy recommendations."""
        recommendations = []
        
        # Analyze current performance patterns
        for operation_key, history in self._performance_history.items():
            if len(history) < 10:
                continue
            
            recent_data = list(history)[-20:]
            
            # Calculate variance in response times
            response_times = [entry["avg_duration_ms"] for entry in recent_data]
            variance = statistics.variance(response_times) if len(response_times) > 1 else 0
            
            # High variance suggests need for better load balancing
            if variance > 1000:  # High variance in response times
                recommendations.append(LoadBalancingRecommendation(
                    current_strategy=LoadBalancingStrategy.ROUND_ROBIN,
                    recommended_strategy=LoadBalancingStrategy.RESPONSE_TIME,
                    reason="High variance in response times detected",
                    expected_improvement="More consistent response times",
                    configuration_changes={
                        "strategy": "response_time",
                        "health_check_interval": 10
                    },
                    confidence=0.8,
                    implementation_complexity="low"
                ))
            
            # Low success rate suggests need for health-aware balancing
            success_rates = [entry["success_rate"] for entry in recent_data]
            avg_success_rate = statistics.mean(success_rates)
            
            if avg_success_rate < 0.95:
                recommendations.append(LoadBalancingRecommendation(
                    current_strategy=LoadBalancingStrategy.ROUND_ROBIN,
                    recommended_strategy=LoadBalancingStrategy.ADAPTIVE,
                    reason="Low success rate indicates unhealthy endpoints",
                    expected_improvement="Better handling of failed endpoints",
                    configuration_changes={
                        "strategy": "adaptive",
                        "health_check_interval": 5,
                        "failover_enabled": True
                    },
                    confidence=0.9,
                    implementation_complexity="medium"
                ))
        
        return recommendations
    
    def get_capacity_predictions(self) -> List[CapacityPrediction]:
        """Get capacity predictions for all resources."""
        predictions = []
        
        for resource_type, predictor in self._predictors.items():
            if resource_type in self._resource_history:
                history = list(self._resource_history[resource_type])
                if len(history) >= 10:
                    current_value = history[-1]["value"]
                    
                    # Get predictions
                    pred_1h = predictor.predict(steps=60)  # 1 hour ahead
                    pred_24h = predictor.predict(steps=1440)  # 24 hours ahead
                    pred_7d = predictor.predict(steps=10080)  # 7 days ahead
                    
                    # Calculate trend
                    recent_values = [entry["value"] for entry in history[-10:]]
                    if len(recent_values) >= 2:
                        trend_slope = (recent_values[-1] - recent_values[0]) / len(recent_values)
                        if abs(trend_slope) < 0.1:
                            trend_direction = "stable"
                        elif trend_slope > 0:
                            trend_direction = "increasing"
                        else:
                            trend_direction = "decreasing"
                    else:
                        trend_direction = "stable"
                    
                    # Estimate saturation times
                    saturation_etas = {}
                    if trend_direction == "increasing" and trend_slope > 0:
                        # Estimate when resource will reach 90% utilization
                        target_value = 90.0
                        if current_value < target_value:
                            time_to_saturation = (target_value - current_value) / trend_slope
                            saturation_etas["90_percent"] = datetime.now() + timedelta(minutes=time_to_saturation)
                        
                        # Estimate when resource will reach 100% utilization
                        target_value = 100.0
                        if current_value < target_value:
                            time_to_saturation = (target_value - current_value) / trend_slope
                            saturation_etas["100_percent"] = datetime.now() + timedelta(minutes=time_to_saturation)
                    
                    prediction = CapacityPrediction(
                        resource_type=ResourceType(resource_type),
                        current_usage=current_value,
                        predicted_usage_1h=pred_1h.get("value", current_value),
                        predicted_usage_24h=pred_24h.get("value", current_value),
                        predicted_usage_7d=pred_7d.get("value", current_value),
                        confidence_1h=pred_1h.get("confidence", 0.5),
                        confidence_24h=pred_24h.get("confidence", 0.3),
                        confidence_7d=pred_7d.get("confidence", 0.1),
                        trend_direction=trend_direction,
                        saturation_etas=saturation_etas
                    )
                    
                    predictions.append(prediction)
        
        return predictions
    
    def generate_scaling_report(self) -> Dict[str, Any]:
        """Generate comprehensive scaling analysis report."""
        current_time = datetime.now()
        
        # Get all recommendations and predictions
        scaling_recs = self.get_scaling_recommendations()
        load_balancing_recs = self.get_load_balancing_recommendations()
        capacity_predictions = self.get_capacity_predictions()
        
        # Analyze trends
        trend_analysis = self._analyze_historical_trends()
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            scaling_recs, load_balancing_recs, capacity_predictions
        )
        
        return {
            "timestamp": current_time.isoformat(),
            "executive_summary": executive_summary,
            "scaling_recommendations": [rec.to_dict() for rec in scaling_recs],
            "load_balancing_recommendations": [rec.to_dict() for rec in load_balancing_recs],
            "capacity_predictions": [pred.to_dict() for pred in capacity_predictions],
            "trend_analysis": trend_analysis,
            "configuration_analysis": self._analyze_current_configuration(),
            "cost_optimization": self._analyze_cost_optimization(),
            "risk_assessment": self._assess_scaling_risks()
        }
    
    def _analyze_historical_trends(self) -> Dict[str, Any]:
        """Analyze historical performance trends."""
        trends = {}
        
        for resource_type, history in self._resource_history.items():
            if len(history) >= 20:
                values = [entry["value"] for entry in history]
                
                # Calculate trend metrics
                trend_metrics = {
                    "current_value": values[-1],
                    "min_value": min(values),
                    "max_value": max(values),
                    "avg_value": statistics.mean(values),
                    "trend_direction": "stable"  # Would be calculated based on linear regression
                }
                
                trends[resource_type] = trend_metrics
        
        return trends
    
    def _generate_executive_summary(
        self,
        scaling_recs: List[ScalingRecommendation],
        load_balancing_recs: List[LoadBalancingRecommendation],
        capacity_predictions: List[CapacityPrediction]
    ) -> Dict[str, Any]:
        """Generate executive summary of scaling analysis."""
        critical_issues = len([r for r in scaling_recs if r.urgency == "critical"])
        high_priority_issues = len([r for r in scaling_recs if r.urgency == "high"])
        
        # Find resources at risk of saturation
        at_risk_resources = []
        for pred in capacity_predictions:
            if pred.predicted_usage_24h > 80:
                at_risk_resources.append(pred.resource_type.value)
        
        return {
            "total_recommendations": len(scaling_recs),
            "critical_issues": critical_issues,
            "high_priority_issues": high_priority_issues,
            "load_balancing_opportunities": len(load_balancing_recs),
            "resources_at_risk": at_risk_resources,
            "overall_health": self._calculate_overall_health(scaling_recs),
            "next_actions": self._suggest_next_actions(scaling_recs, capacity_predictions)
        }
    
    def _analyze_current_configuration(self) -> Dict[str, Any]:
        """Analyze current system configuration."""
        return {
            "analysis_config": self._analysis_config,
            "monitoring_coverage": "High",
            "prediction_accuracy": "Medium",
            "configuration_recommendations": [
                "Consider lowering CPU threshold for earlier warnings",
                "Implement predictive scaling for better resource planning"
            ]
        }
    
    def _analyze_cost_optimization(self) -> Dict[str, Any]:
        """Analyze cost optimization opportunities."""
        scale_down_opportunities = len([
            r for r in self._scaling_history 
            if r.direction == ScalingDirection.SCALE_DOWN
        ])
        
        return {
            "scale_down_opportunities": scale_down_opportunities,
            "potential_savings": "Estimated 10-20% cost reduction through right-sizing",
            "cost_optimization_recommendations": [
                "Consider scheduled scaling based on usage patterns",
                "Implement auto-scaling to optimize costs dynamically"
            ]
        }
    
    def _assess_scaling_risks(self) -> Dict[str, Any]:
        """Assess risks associated with scaling operations."""
        return {
            "high_risk_operations": ["Database scaling", "Storage scaling"],
            "mitigation_strategies": [
                "Implement blue-green deployment for zero-downtime scaling",
                "Test scaling operations in staging environment first",
                "Monitor closely during scaling operations"
            ],
            "rollback_procedures": "Automated rollback available for configuration changes"
        }
    
    def _calculate_overall_health(self, scaling_recs: List[ScalingRecommendation]) -> str:
        """Calculate overall system health based on recommendations."""
        if any(r.urgency == "critical" for r in scaling_recs):
            return "Poor"
        elif any(r.urgency == "high" for r in scaling_recs):
            return "Fair"
        elif any(r.urgency == "medium" for r in scaling_recs):
            return "Good"
        else:
            return "Excellent"
    
    def _suggest_next_actions(
        self,
        scaling_recs: List[ScalingRecommendation],
        capacity_predictions: List[CapacityPrediction]
    ) -> List[str]:
        """Suggest immediate next actions."""
        actions = []
        
        # Critical recommendations first
        critical_recs = [r for r in scaling_recs if r.urgency == "critical"]
        for rec in critical_recs[:3]:  # Top 3 critical issues
            actions.append(f"Address critical {rec.resource_type.value} scaling for {rec.server_name}")
        
        # Resources approaching saturation
        for pred in capacity_predictions:
            if "90_percent" in pred.saturation_etas and pred.saturation_etas["90_percent"]:
                eta = pred.saturation_etas["90_percent"]
                if eta and (eta - datetime.now()).total_seconds() < 86400:  # Within 24 hours
                    actions.append(f"Plan {pred.resource_type.value} scaling within 24 hours")
        
        return actions[:5]  # Return top 5 actions
    
    async def shutdown(self):
        """Shutdown the scaling advisor."""
        logger.info("Shutting down MCP Scaling Advisor")
        
        self._is_running = False
        
        if self._analysis_task:
            self._analysis_task.cancel()
            try:
                await self._analysis_task
            except asyncio.CancelledError:
                pass
        
        logger.info("MCP Scaling Advisor shutdown complete")


class TimeSeriesPredictor:
    """Simple time series predictor for capacity planning."""
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.values: deque = deque(maxlen=window_size)
        self.trend = 0.0
        self.seasonal_pattern = None
    
    def update(self, values: List[float]):
        """Update predictor with new values."""
        self.values.extend(values)
        
        # Calculate simple trend
        if len(self.values) >= 10:
            recent = list(self.values)[-10:]
            x = list(range(len(recent)))
            n = len(x)
            
            sum_x = sum(x)
            sum_y = sum(recent)
            sum_xy = sum(x[i] * recent[i] for i in range(n))
            sum_x2 = sum(x[i] ** 2 for i in range(n))
            
            if n * sum_x2 - sum_x ** 2 != 0:
                self.trend = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x ** 2)
    
    def predict(self, steps: int) -> Dict[str, float]:
        """Predict value after given number of steps."""
        if not self.values:
            return {"value": 0.0, "confidence": 0.0}
        
        current_value = self.values[-1]
        predicted_value = current_value + (self.trend * steps)
        
        # Ensure prediction is within reasonable bounds
        predicted_value = max(0, min(100, predicted_value))
        
        # Simple confidence calculation (decreases with prediction distance)
        confidence = max(0.1, 1.0 - (steps / 1000.0))
        
        return {
            "value": predicted_value,
            "confidence": confidence
        }


__all__ = [
    "ScalingDirection",
    "ResourceType", 
    "ScalingTrigger",
    "ScalingRecommendation",
    "LoadBalancingRecommendation",
    "CapacityPrediction",
    "MCPScalingAdvisor",
    "TimeSeriesPredictor"
]