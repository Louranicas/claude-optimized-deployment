"""
Performance metrics and monitoring for MCP learning system
"""

import asyncio
import time
from collections import deque, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from prometheus_client import Counter, Histogram, Gauge, Summary
import structlog

logger = structlog.get_logger(__name__)


# Prometheus metrics
REQUESTS_TOTAL = Counter('mcp_requests_total', 'Total requests processed', ['server_type', 'status'])
REQUEST_DURATION = Histogram('mcp_request_duration_seconds', 'Request duration', ['server_type'])
LEARNING_CYCLES = Counter('mcp_learning_cycles_total', 'Total learning cycles completed', ['model_type'])
PATTERN_DISCOVERIES = Counter('mcp_patterns_discovered_total', 'Patterns discovered', ['pattern_type'])
MODEL_ACCURACY = Gauge('mcp_model_accuracy', 'Model prediction accuracy', ['model_name'])
MEMORY_USAGE = Gauge('mcp_memory_usage_bytes', 'Memory usage in bytes', ['component'])
ACTIVE_SESSIONS = Gauge('mcp_active_sessions', 'Number of active sessions')
PREDICTION_CONFIDENCE = Summary('mcp_prediction_confidence', 'Prediction confidence scores')


@dataclass
class PerformanceMetrics:
    """Container for performance metrics"""
    timestamp: datetime
    execution_time_ms: float
    cpu_usage_percent: float
    memory_usage_mb: float
    success: bool
    command_type: str
    error_type: Optional[str] = None
    queue_depth: int = 0
    cache_hit: bool = False


@dataclass
class LearningMetricsData:
    """Container for learning metrics"""
    timestamp: datetime
    model_name: str
    accuracy: float
    loss: float
    predictions_made: int
    training_samples: int
    learning_rate: float
    patterns_discovered: Dict[str, int] = field(default_factory=dict)


class MovingAverage:
    """Efficient moving average calculator"""
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.values = deque(maxlen=window_size)
        self.sum = 0.0
        
    def add(self, value: float):
        """Add value to moving average"""
        if len(self.values) == self.window_size:
            self.sum -= self.values[0]
        self.values.append(value)
        self.sum += value
        
    @property
    def average(self) -> float:
        """Get current average"""
        return self.sum / len(self.values) if self.values else 0.0
        
    @property
    def std_dev(self) -> float:
        """Get standard deviation"""
        if len(self.values) < 2:
            return 0.0
        avg = self.average
        variance = sum((x - avg) ** 2 for x in self.values) / len(self.values)
        return np.sqrt(variance)


class PerformanceTracker:
    """Track and analyze performance metrics"""
    
    def __init__(self, history_size: int = 10000):
        self.history_size = history_size
        self.metrics_history = deque(maxlen=history_size)
        self.command_metrics: Dict[str, MovingAverage] = defaultdict(lambda: MovingAverage())
        self.error_counts: Dict[str, int] = defaultdict(int)
        self.start_time = time.time()
        
        # Time-based aggregations
        self.minute_metrics = deque(maxlen=60)
        self.hour_metrics = deque(maxlen=24)
        self.last_minute_update = datetime.now()
        
    def record_request(self, request: Dict[str, Any], response: Dict[str, Any], metrics: Dict[str, float]):
        """Record request metrics"""
        command_type = request.get("type", "unknown")
        success = response.get("status") == "success"
        
        # Create metrics object
        perf_metrics = PerformanceMetrics(
            timestamp=datetime.now(),
            execution_time_ms=metrics.get("execution_time", 0),
            cpu_usage_percent=metrics.get("cpu_usage", 0),
            memory_usage_mb=metrics.get("memory_usage", 0),
            success=success,
            command_type=command_type,
            error_type=response.get("error_type") if not success else None,
            queue_depth=metrics.get("queue_depth", 0),
            cache_hit=metrics.get("cache_hit", False)
        )
        
        # Store in history
        self.metrics_history.append(perf_metrics)
        
        # Update moving averages
        self.command_metrics[command_type].add(perf_metrics.execution_time_ms)
        
        # Update error counts
        if not success:
            self.error_counts[perf_metrics.error_type or "unknown"] += 1
            
        # Update Prometheus metrics
        REQUESTS_TOTAL.labels(
            server_type=request.get("server_type", "unknown"),
            status="success" if success else "error"
        ).inc()
        
        REQUEST_DURATION.labels(
            server_type=request.get("server_type", "unknown")
        ).observe(perf_metrics.execution_time_ms / 1000.0)
        
        MEMORY_USAGE.labels(component="process").set(perf_metrics.memory_usage_mb * 1024 * 1024)
        
        # Update time-based aggregations
        self._update_time_aggregations()
        
    def _update_time_aggregations(self):
        """Update minute and hour aggregations"""
        now = datetime.now()
        
        if (now - self.last_minute_update) >= timedelta(minutes=1):
            # Calculate minute metrics
            recent_metrics = [
                m for m in self.metrics_history
                if (now - m.timestamp) <= timedelta(minutes=1)
            ]
            
            if recent_metrics:
                minute_summary = {
                    "timestamp": now,
                    "requests": len(recent_metrics),
                    "avg_execution_time": np.mean([m.execution_time_ms for m in recent_metrics]),
                    "success_rate": sum(1 for m in recent_metrics if m.success) / len(recent_metrics),
                    "avg_cpu": np.mean([m.cpu_usage_percent for m in recent_metrics]),
                    "avg_memory": np.mean([m.memory_usage_mb for m in recent_metrics]),
                }
                
                self.minute_metrics.append(minute_summary)
                self.last_minute_update = now
                
    def get_summary(self) -> Dict[str, Any]:
        """Get performance summary"""
        if not self.metrics_history:
            return {
                "total_requests": 0,
                "uptime_seconds": time.time() - self.start_time,
                "error_rate": 0.0,
                "avg_execution_time_ms": 0.0,
            }
            
        total_requests = len(self.metrics_history)
        successful_requests = sum(1 for m in self.metrics_history if m.success)
        
        # Calculate percentiles
        execution_times = [m.execution_time_ms for m in self.metrics_history]
        
        return {
            "total_requests": total_requests,
            "successful_requests": successful_requests,
            "error_rate": 1 - (successful_requests / total_requests),
            "uptime_seconds": time.time() - self.start_time,
            "avg_execution_time_ms": np.mean(execution_times),
            "p50_execution_time_ms": np.percentile(execution_times, 50),
            "p95_execution_time_ms": np.percentile(execution_times, 95),
            "p99_execution_time_ms": np.percentile(execution_times, 99),
            "command_type_metrics": self._get_command_type_metrics(),
            "error_breakdown": dict(self.error_counts),
            "cache_hit_rate": self._calculate_cache_hit_rate(),
            "recent_trend": self._get_recent_trend(),
        }
        
    def _get_command_type_metrics(self) -> Dict[str, Dict[str, float]]:
        """Get metrics by command type"""
        result = {}
        
        for cmd_type, moving_avg in self.command_metrics.items():
            cmd_metrics = [m for m in self.metrics_history if m.command_type == cmd_type]
            
            if cmd_metrics:
                result[cmd_type] = {
                    "count": len(cmd_metrics),
                    "avg_execution_time_ms": moving_avg.average,
                    "std_dev": moving_avg.std_dev,
                    "success_rate": sum(1 for m in cmd_metrics if m.success) / len(cmd_metrics),
                }
                
        return result
        
    def _calculate_cache_hit_rate(self) -> float:
        """Calculate cache hit rate"""
        recent = list(self.metrics_history)[-1000:]  # Last 1000 requests
        if not recent:
            return 0.0
            
        cache_hits = sum(1 for m in recent if m.cache_hit)
        return cache_hits / len(recent)
        
    def _get_recent_trend(self) -> Dict[str, Any]:
        """Get recent performance trend"""
        if len(self.minute_metrics) < 2:
            return {"trend": "stable", "change_percent": 0.0}
            
        recent_minutes = list(self.minute_metrics)[-10:]
        older_minutes = list(self.minute_metrics)[-20:-10]
        
        if not older_minutes:
            return {"trend": "stable", "change_percent": 0.0}
            
        recent_avg = np.mean([m["avg_execution_time"] for m in recent_minutes])
        older_avg = np.mean([m["avg_execution_time"] for m in older_minutes])
        
        change_percent = ((recent_avg - older_avg) / older_avg) * 100 if older_avg > 0 else 0
        
        if change_percent > 10:
            trend = "degrading"
        elif change_percent < -10:
            trend = "improving"
        else:
            trend = "stable"
            
        return {
            "trend": trend,
            "change_percent": change_percent,
            "recent_avg_ms": recent_avg,
            "older_avg_ms": older_avg,
        }
        
    def get_anomalies(self, threshold_std: float = 3.0) -> List[PerformanceMetrics]:
        """Detect performance anomalies"""
        anomalies = []
        
        for cmd_type, moving_avg in self.command_metrics.items():
            avg = moving_avg.average
            std = moving_avg.std_dev
            
            if std > 0:
                # Find metrics that deviate significantly
                cmd_anomalies = [
                    m for m in self.metrics_history
                    if m.command_type == cmd_type and
                    abs(m.execution_time_ms - avg) > threshold_std * std
                ]
                anomalies.extend(cmd_anomalies)
                
        return sorted(anomalies, key=lambda x: x.execution_time_ms, reverse=True)


class LearningMetrics:
    """Track learning algorithm performance"""
    
    def __init__(self):
        self.metrics_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.current_metrics: Dict[str, LearningMetricsData] = {}
        self.pattern_counts: Dict[str, int] = defaultdict(int)
        
    def record_training_step(self, model_name: str, loss: float, accuracy: float, batch_size: int):
        """Record training step metrics"""
        metrics = LearningMetricsData(
            timestamp=datetime.now(),
            model_name=model_name,
            accuracy=accuracy,
            loss=loss,
            predictions_made=0,
            training_samples=batch_size,
            learning_rate=0.001,  # Should be passed as parameter
        )
        
        self.metrics_history[model_name].append(metrics)
        self.current_metrics[model_name] = metrics
        
        # Update Prometheus metrics
        MODEL_ACCURACY.labels(model_name=model_name).set(accuracy)
        LEARNING_CYCLES.labels(model_type=model_name).inc()
        
    def record_prediction(self, model_name: str, confidence: float, correct: Optional[bool] = None):
        """Record prediction metrics"""
        if model_name in self.current_metrics:
            self.current_metrics[model_name].predictions_made += 1
            
        PREDICTION_CONFIDENCE.observe(confidence)
        
    def record_pattern_discovery(self, pattern_type: str, count: int = 1):
        """Record pattern discovery"""
        self.pattern_counts[pattern_type] += count
        PATTERN_DISCOVERIES.labels(pattern_type=pattern_type).inc(count)
        
    def get_model_performance(self, model_name: str) -> Dict[str, Any]:
        """Get model performance metrics"""
        if model_name not in self.metrics_history:
            return {"error": "No metrics for model"}
            
        history = list(self.metrics_history[model_name])
        
        if not history:
            return {"error": "No metrics history"}
            
        recent = history[-100:]  # Last 100 entries
        
        return {
            "model_name": model_name,
            "current_accuracy": history[-1].accuracy if history else 0.0,
            "avg_accuracy": np.mean([m.accuracy for m in recent]),
            "accuracy_trend": self._calculate_trend([m.accuracy for m in recent]),
            "avg_loss": np.mean([m.loss for m in recent]),
            "total_predictions": sum(m.predictions_made for m in history),
            "total_training_samples": sum(m.training_samples for m in history),
            "training_steps": len(history),
            "last_updated": history[-1].timestamp.isoformat() if history else None,
        }
        
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend from values"""
        if len(values) < 10:
            return "insufficient_data"
            
        # Simple linear regression
        x = np.arange(len(values))
        slope, _ = np.polyfit(x, values, 1)
        
        if slope > 0.001:
            return "improving"
        elif slope < -0.001:
            return "degrading"
        else:
            return "stable"
            
    def get_learning_summary(self) -> Dict[str, Any]:
        """Get comprehensive learning metrics summary"""
        model_summaries = {}
        
        for model_name in self.metrics_history:
            model_summaries[model_name] = self.get_model_performance(model_name)
            
        return {
            "models": model_summaries,
            "total_patterns_discovered": sum(self.pattern_counts.values()),
            "pattern_breakdown": dict(self.pattern_counts),
            "active_models": len(self.current_metrics),
            "last_update": max(
                (m.timestamp for m in self.current_metrics.values()),
                default=datetime.now()
            ).isoformat(),
        }


class PredictionAccuracy:
    """Track prediction accuracy over time"""
    
    def __init__(self, window_size: int = 1000):
        self.predictions = deque(maxlen=window_size)
        self.accuracy_by_type: Dict[str, MovingAverage] = defaultdict(lambda: MovingAverage(100))
        
    def record_prediction(self, predicted: str, actual: str, confidence: float, prediction_type: str):
        """Record prediction result"""
        correct = predicted == actual
        
        self.predictions.append({
            "predicted": predicted,
            "actual": actual,
            "correct": correct,
            "confidence": confidence,
            "type": prediction_type,
            "timestamp": datetime.now(),
        })
        
        # Update accuracy by type
        self.accuracy_by_type[prediction_type].add(1.0 if correct else 0.0)
        
    def get_accuracy_report(self) -> Dict[str, Any]:
        """Get accuracy report"""
        if not self.predictions:
            return {"overall_accuracy": 0.0, "predictions_made": 0}
            
        correct_predictions = sum(1 for p in self.predictions if p["correct"])
        overall_accuracy = correct_predictions / len(self.predictions)
        
        # Accuracy by confidence buckets
        confidence_buckets = defaultdict(lambda: {"correct": 0, "total": 0})
        
        for pred in self.predictions:
            bucket = int(pred["confidence"] * 10) / 10  # Round to nearest 0.1
            confidence_buckets[bucket]["total"] += 1
            if pred["correct"]:
                confidence_buckets[bucket]["correct"] += 1
                
        confidence_accuracy = {
            f"{bucket:.1f}": data["correct"] / data["total"] if data["total"] > 0 else 0
            for bucket, data in confidence_buckets.items()
        }
        
        return {
            "overall_accuracy": overall_accuracy,
            "predictions_made": len(self.predictions),
            "correct_predictions": correct_predictions,
            "accuracy_by_type": {
                pred_type: avg.average
                for pred_type, avg in self.accuracy_by_type.items()
            },
            "confidence_accuracy": confidence_accuracy,
            "recent_accuracy": self._get_recent_accuracy(100),
        }
        
    def _get_recent_accuracy(self, n: int) -> float:
        """Get accuracy of recent N predictions"""
        recent = list(self.predictions)[-n:]
        if not recent:
            return 0.0
            
        correct = sum(1 for p in recent if p["correct"])
        return correct / len(recent)


class OptimizationMetrics:
    """Track optimization effectiveness"""
    
    def __init__(self):
        self.optimizations = deque(maxlen=1000)
        self.baseline_metrics: Dict[str, float] = {}
        self.optimization_impact: Dict[str, MovingAverage] = defaultdict(lambda: MovingAverage())
        
    def record_optimization(
        self,
        optimization_type: str,
        baseline_metric: float,
        optimized_metric: float,
        context: Dict[str, Any]
    ):
        """Record optimization result"""
        improvement = (baseline_metric - optimized_metric) / baseline_metric if baseline_metric > 0 else 0
        
        self.optimizations.append({
            "type": optimization_type,
            "baseline": baseline_metric,
            "optimized": optimized_metric,
            "improvement": improvement,
            "context": context,
            "timestamp": datetime.now(),
        })
        
        self.optimization_impact[optimization_type].add(improvement)
        
    def get_optimization_report(self) -> Dict[str, Any]:
        """Get optimization effectiveness report"""
        if not self.optimizations:
            return {"optimizations_applied": 0, "avg_improvement": 0.0}
            
        total_baseline = sum(opt["baseline"] for opt in self.optimizations)
        total_optimized = sum(opt["optimized"] for opt in self.optimizations)
        overall_improvement = (total_baseline - total_optimized) / total_baseline if total_baseline > 0 else 0
        
        # Best performing optimizations
        impact_by_type = {
            opt_type: avg.average
            for opt_type, avg in self.optimization_impact.items()
        }
        
        best_optimizations = sorted(
            impact_by_type.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        return {
            "optimizations_applied": len(self.optimizations),
            "overall_improvement": overall_improvement,
            "avg_improvement": np.mean([opt["improvement"] for opt in self.optimizations]),
            "best_optimizations": best_optimizations,
            "recent_optimizations": [
                {
                    "type": opt["type"],
                    "improvement": opt["improvement"],
                    "timestamp": opt["timestamp"].isoformat(),
                }
                for opt in list(self.optimizations)[-10:]
            ],
        }
        
    def should_apply_optimization(self, optimization_type: str, threshold: float = 0.05) -> bool:
        """Decide if optimization should be applied based on historical performance"""
        if optimization_type not in self.optimization_impact:
            return True  # Try new optimizations
            
        avg_impact = self.optimization_impact[optimization_type].average
        return avg_impact >= threshold


# Global metrics instance
performance_tracker = PerformanceTracker()
learning_metrics = LearningMetrics()
prediction_accuracy = PredictionAccuracy()
optimization_metrics = OptimizationMetrics()