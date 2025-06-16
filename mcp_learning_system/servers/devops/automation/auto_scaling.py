#!/usr/bin/env python3
"""
Auto-scaling automation for DevOps MCP Server
Implements predictive and reactive scaling based on learned patterns
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import yaml
import json
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class ScalingDirection(Enum):
    UP = "scale_up"
    DOWN = "scale_down"
    NONE = "no_change"

@dataclass
class ScalingDecision:
    service: str
    direction: ScalingDirection
    current_replicas: int
    target_replicas: int
    reason: str
    confidence: float
    estimated_impact: Dict[str, float]

@dataclass
class ServiceMetrics:
    service: str
    cpu_usage: float
    memory_usage: float
    request_rate: float
    error_rate: float
    response_time: float
    current_replicas: int

class PredictiveScaler:
    def __init__(self, config_path: str):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
            
        self.scaling_policies = self.config.get('scaling_policies', {})
        self.prediction_window = timedelta(minutes=30)
        self.scaling_history = []
        
    async def analyze_scaling_needs(self, 
                                  metrics: List[ServiceMetrics],
                                  predictions: Dict[str, Dict]) -> List[ScalingDecision]:
        """Analyze current metrics and predictions to make scaling decisions"""
        decisions = []
        
        for service_metrics in metrics:
            # Get service-specific policy
            policy = self.scaling_policies.get(service_metrics.service, 
                                              self.scaling_policies.get('default', {}))
            
            # Analyze current state
            current_analysis = self._analyze_current_metrics(service_metrics, policy)
            
            # Get predicted load
            service_predictions = predictions.get(service_metrics.service, {})
            predicted_analysis = self._analyze_predictions(service_predictions, policy)
            
            # Make scaling decision
            decision = self._make_scaling_decision(
                service_metrics,
                current_analysis,
                predicted_analysis,
                policy
            )
            
            if decision.direction != ScalingDirection.NONE:
                decisions.append(decision)
                
        return decisions
    
    def _analyze_current_metrics(self, 
                               metrics: ServiceMetrics, 
                               policy: Dict) -> Dict[str, bool]:
        """Analyze current metrics against thresholds"""
        analysis = {
            'cpu_high': metrics.cpu_usage > policy.get('cpu_threshold_high', 0.8),
            'cpu_low': metrics.cpu_usage < policy.get('cpu_threshold_low', 0.2),
            'memory_high': metrics.memory_usage > policy.get('memory_threshold_high', 0.85),
            'memory_low': metrics.memory_usage < policy.get('memory_threshold_low', 0.3),
            'error_rate_high': metrics.error_rate > policy.get('error_rate_threshold', 0.01),
            'response_time_high': metrics.response_time > policy.get('response_time_threshold', 500),
        }
        
        # Check request rate
        rps_per_replica = metrics.request_rate / max(1, metrics.current_replicas)
        analysis['high_load'] = rps_per_replica > policy.get('max_rps_per_replica', 100)
        analysis['low_load'] = rps_per_replica < policy.get('min_rps_per_replica', 10)
        
        return analysis
    
    def _analyze_predictions(self, 
                           predictions: Dict,
                           policy: Dict) -> Dict[str, Any]:
        """Analyze predicted metrics"""
        if not predictions:
            return {'confidence': 0.0, 'predicted_load': 'unknown'}
            
        analysis = {
            'confidence': predictions.get('confidence', 0.0),
            'predicted_cpu': predictions.get('predicted_cpu', 0.0),
            'predicted_memory': predictions.get('predicted_memory', 0.0),
            'predicted_requests': predictions.get('predicted_requests', 0.0),
            'time_to_peak': predictions.get('time_to_peak_minutes', 0),
        }
        
        # Determine predicted load level
        if analysis['predicted_cpu'] > policy.get('cpu_threshold_high', 0.8):
            analysis['predicted_load'] = 'high'
        elif analysis['predicted_cpu'] < policy.get('cpu_threshold_low', 0.2):
            analysis['predicted_load'] = 'low'
        else:
            analysis['predicted_load'] = 'normal'
            
        return analysis
    
    def _make_scaling_decision(self,
                             metrics: ServiceMetrics,
                             current_analysis: Dict[str, bool],
                             predicted_analysis: Dict[str, Any],
                             policy: Dict) -> ScalingDecision:
        """Make scaling decision based on current and predicted state"""
        
        # Immediate scaling needs (reactive)
        if any([current_analysis['cpu_high'], 
                current_analysis['memory_high'],
                current_analysis['error_rate_high'],
                current_analysis['response_time_high']]):
            
            # Calculate scale up amount
            scale_factor = policy.get('scale_up_factor', 1.5)
            target_replicas = min(
                int(metrics.current_replicas * scale_factor),
                policy.get('max_replicas', 100)
            )
            
            return ScalingDecision(
                service=metrics.service,
                direction=ScalingDirection.UP,
                current_replicas=metrics.current_replicas,
                target_replicas=target_replicas,
                reason="High resource utilization or performance degradation",
                confidence=0.95,
                estimated_impact={
                    'cpu_reduction': (metrics.cpu_usage * metrics.current_replicas) / target_replicas,
                    'response_time_improvement': 0.3,
                }
            )
            
        # Scale down if underutilized
        if all([current_analysis['cpu_low'],
                current_analysis['memory_low'],
                current_analysis['low_load']]) and \
           predicted_analysis.get('predicted_load') != 'high':
            
            scale_factor = policy.get('scale_down_factor', 0.75)
            target_replicas = max(
                int(metrics.current_replicas * scale_factor),
                policy.get('min_replicas', 2)
            )
            
            if target_replicas < metrics.current_replicas:
                return ScalingDecision(
                    service=metrics.service,
                    direction=ScalingDirection.DOWN,
                    current_replicas=metrics.current_replicas,
                    target_replicas=target_replicas,
                    reason="Low resource utilization",
                    confidence=0.8,
                    estimated_impact={
                        'cost_savings': (metrics.current_replicas - target_replicas) * 0.05,
                        'efficiency_gain': 0.2,
                    }
                )
                
        # Predictive scaling
        if predicted_analysis.get('confidence', 0) > 0.7:
            if predicted_analysis.get('predicted_load') == 'high' and \
               predicted_analysis.get('time_to_peak', 30) < 15:
                
                # Preemptive scale up
                target_replicas = min(
                    int(metrics.current_replicas * 1.3),
                    policy.get('max_replicas', 100)
                )
                
                return ScalingDecision(
                    service=metrics.service,
                    direction=ScalingDirection.UP,
                    current_replicas=metrics.current_replicas,
                    target_replicas=target_replicas,
                    reason=f"Predicted high load in {predicted_analysis['time_to_peak']} minutes",
                    confidence=predicted_analysis['confidence'],
                    estimated_impact={
                        'prevented_degradation': 0.8,
                        'readiness_improvement': 0.9,
                    }
                )
                
        # No scaling needed
        return ScalingDecision(
            service=metrics.service,
            direction=ScalingDirection.NONE,
            current_replicas=metrics.current_replicas,
            target_replicas=metrics.current_replicas,
            reason="Metrics within normal range",
            confidence=1.0,
            estimated_impact={}
        )
    
    async def execute_scaling(self, decision: ScalingDecision) -> Dict[str, Any]:
        """Execute scaling decision"""
        logger.info(f"Executing scaling decision for {decision.service}: "
                   f"{decision.current_replicas} -> {decision.target_replicas}")
        
        # Record decision
        self.scaling_history.append({
            'timestamp': datetime.utcnow(),
            'decision': decision,
        })
        
        # In production, this would call actual scaling APIs
        # For now, return a mock result
        result = {
            'success': True,
            'service': decision.service,
            'previous_replicas': decision.current_replicas,
            'new_replicas': decision.target_replicas,
            'execution_time': 5.2,
            'message': f"Successfully scaled {decision.service}",
        }
        
        return result

class AutoScalingOrchestrator:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.scaler = PredictiveScaler(config_path)
        self.running = False
        
    async def start(self):
        """Start auto-scaling orchestration"""
        self.running = True
        logger.info("Auto-scaling orchestrator started")
        
        while self.running:
            try:
                # Collect metrics (mock data for example)
                metrics = await self._collect_metrics()
                
                # Get predictions
                predictions = await self._get_predictions()
                
                # Analyze and make decisions
                decisions = await self.scaler.analyze_scaling_needs(metrics, predictions)
                
                # Execute scaling decisions
                for decision in decisions:
                    result = await self.scaler.execute_scaling(decision)
                    logger.info(f"Scaling result: {result}")
                    
                # Wait before next iteration
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in auto-scaling loop: {e}")
                await asyncio.sleep(60)  # Back off on error
                
    async def stop(self):
        """Stop auto-scaling orchestration"""
        self.running = False
        logger.info("Auto-scaling orchestrator stopped")
        
    async def _collect_metrics(self) -> List[ServiceMetrics]:
        """Collect current metrics for all services"""
        # In production, this would query actual metrics
        # Mock data for example
        return [
            ServiceMetrics(
                service="api-service",
                cpu_usage=0.75,
                memory_usage=0.65,
                request_rate=850,
                error_rate=0.005,
                response_time=120,
                current_replicas=5
            ),
            ServiceMetrics(
                service="worker-service",
                cpu_usage=0.15,
                memory_usage=0.20,
                request_rate=50,
                error_rate=0.001,
                response_time=50,
                current_replicas=10
            ),
        ]
        
    async def _get_predictions(self) -> Dict[str, Dict]:
        """Get load predictions for services"""
        # In production, this would call the learning engine
        # Mock predictions for example
        return {
            "api-service": {
                "confidence": 0.85,
                "predicted_cpu": 0.90,
                "predicted_memory": 0.75,
                "predicted_requests": 1200,
                "time_to_peak_minutes": 10,
            },
            "worker-service": {
                "confidence": 0.75,
                "predicted_cpu": 0.10,
                "predicted_memory": 0.15,
                "predicted_requests": 30,
                "time_to_peak_minutes": 60,
            },
        }

# Configuration for auto-scaling policies
DEFAULT_CONFIG = """
scaling_policies:
  default:
    min_replicas: 2
    max_replicas: 50
    cpu_threshold_high: 0.8
    cpu_threshold_low: 0.2
    memory_threshold_high: 0.85
    memory_threshold_low: 0.3
    error_rate_threshold: 0.01
    response_time_threshold: 500
    max_rps_per_replica: 100
    min_rps_per_replica: 10
    scale_up_factor: 1.5
    scale_down_factor: 0.75
    
  api-service:
    min_replicas: 3
    max_replicas: 100
    cpu_threshold_high: 0.75
    response_time_threshold: 200
    max_rps_per_replica: 200
    
  worker-service:
    min_replicas: 5
    max_replicas: 200
    cpu_threshold_high: 0.9
    memory_threshold_high: 0.9
    scale_up_factor: 2.0
"""

async def main():
    """Main function for testing"""
    # Create config file
    with open('/tmp/scaling_config.yaml', 'w') as f:
        f.write(DEFAULT_CONFIG)
        
    # Create and start orchestrator
    orchestrator = AutoScalingOrchestrator('/tmp/scaling_config.yaml')
    
    try:
        # Run for a limited time for testing
        task = asyncio.create_task(orchestrator.start())
        await asyncio.sleep(10)  # Run for 10 seconds
        await orchestrator.stop()
        
    except KeyboardInterrupt:
        await orchestrator.stop()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())