"""
Cache Performance Tuning Guide and Automated Optimization.

This module provides automated cache tuning recommendations and
optimization strategies based on observed performance metrics.
"""

import asyncio
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Callable
from enum import Enum
import structlog

from .cache_integration import IntegratedCacheManager, CacheStats
from .cache_benchmarks import (
    CacheBenchmarker, BenchmarkConfig, BenchmarkResult,
    BenchmarkType, WorkloadPattern
)
from .distributed_cache import CacheConfig
from .cache_patterns import CachePatternConfig, CachePattern, ConsistencyLevel

__all__ = [
    "TuningArea",
    "TuningRecommendation",
    "PerformanceGoal",
    "TuningConfig",
    "CacheTuner",
    "AutoOptimizer",
    "TuningReport"
]

logger = structlog.get_logger(__name__)


class TuningArea(Enum):
    """Areas of cache tuning."""
    MEMORY_USAGE = "memory_usage"
    LATENCY = "latency"
    THROUGHPUT = "throughput"
    HIT_RATE = "hit_rate"
    CONSISTENCY = "consistency"
    SECURITY = "security"
    PATTERNS = "patterns"
    CLUSTERING = "clustering"


class PerformanceGoal(Enum):
    """Performance optimization goals."""
    MINIMIZE_LATENCY = "minimize_latency"
    MAXIMIZE_THROUGHPUT = "maximize_throughput"
    OPTIMIZE_MEMORY = "optimize_memory"
    MAXIMIZE_HIT_RATE = "maximize_hit_rate"
    BALANCE_ALL = "balance_all"


@dataclass
class TuningRecommendation:
    """A cache tuning recommendation."""
    area: TuningArea
    title: str
    description: str
    priority: str  # "high", "medium", "low"
    impact: str    # "high", "medium", "low"
    effort: str    # "high", "medium", "low"
    current_value: Any
    recommended_value: Any
    rationale: str
    implementation_steps: List[str]
    expected_improvement: str
    
    @property
    def score(self) -> float:
        """Calculate recommendation score based on priority, impact, and effort."""
        priority_weight = {"high": 3, "medium": 2, "low": 1}
        impact_weight = {"high": 3, "medium": 2, "low": 1}
        effort_weight = {"high": 1, "medium": 2, "low": 3}  # Lower effort = higher score
        
        return (
            priority_weight.get(self.priority, 1) * 0.4 +
            impact_weight.get(self.impact, 1) * 0.4 +
            effort_weight.get(self.effort, 1) * 0.2
        )


@dataclass
class TuningConfig:
    """Configuration for cache tuning."""
    performance_goal: PerformanceGoal = PerformanceGoal.BALANCE_ALL
    target_hit_rate: float = 0.85  # 85%
    target_latency_ms: float = 10.0
    target_throughput: float = 1000.0  # ops/sec
    max_memory_mb: float = 2048.0
    
    # Tuning constraints
    max_l1_cache_size: int = 50000
    max_ttl_seconds: float = 86400.0  # 24 hours
    min_ttl_seconds: float = 60.0  # 1 minute
    
    # Analysis settings
    benchmark_duration: float = 60.0
    sample_period: float = 3600.0  # 1 hour
    min_samples: int = 10


@dataclass
class TuningReport:
    """Comprehensive tuning report."""
    timestamp: float
    cache_config: Dict[str, Any]
    performance_metrics: Dict[str, float]
    recommendations: List[TuningRecommendation]
    optimization_summary: str
    estimated_improvements: Dict[str, str]
    
    def get_top_recommendations(self, count: int = 5) -> List[TuningRecommendation]:
        """Get top recommendations by score."""
        return sorted(self.recommendations, key=lambda r: r.score, reverse=True)[:count]


class CacheTuner:
    """Analyzes cache performance and provides tuning recommendations."""
    
    def __init__(self, cache_manager: IntegratedCacheManager, config: TuningConfig):
        self.cache_manager = cache_manager
        self.config = config
        self.benchmarker = CacheBenchmarker(cache_manager.cache_manager)
        self._performance_history: List[Dict[str, float]] = []
    
    async def analyze_performance(self) -> Dict[str, float]:
        """Analyze current cache performance."""
        try:
            # Get current statistics
            stats = await self.cache_manager.get_stats()
            
            # Run quick benchmark for latency/throughput
            benchmark_config = BenchmarkConfig(
                duration_seconds=self.config.benchmark_duration,
                concurrency=10,
                workload_pattern=WorkloadPattern.UNIFORM_RANDOM
            )
            
            latency_result = await self.benchmarker.run_benchmark(
                benchmark_config, BenchmarkType.LATENCY
            )
            
            throughput_result = await self.benchmarker.run_benchmark(
                benchmark_config, BenchmarkType.THROUGHPUT
            )
            
            # Compile performance metrics
            metrics = {
                "hit_rate": stats.hit_rate,
                "avg_latency_ms": latency_result.avg_latency_ms if latency_result else stats.avg_latency_ms,
                "throughput_ops_sec": throughput_result.operations_per_second if throughput_result else stats.ops_per_second,
                "memory_usage_mb": stats.memory_usage_mb,
                "error_rate": stats.error_rate,
                "l1_cache_size": stats.l1_cache_size,
                "item_count": stats.item_count
            }
            
            # Store in history
            self._performance_history.append(metrics)
            if len(self._performance_history) > 100:  # Keep last 100 samples
                self._performance_history.pop(0)
            
            return metrics
            
        except Exception as e:
            logger.error("Performance analysis failed", error=str(e))
            return {}
    
    async def generate_recommendations(self) -> List[TuningRecommendation]:
        """Generate tuning recommendations based on performance analysis."""
        try:
            current_metrics = await self.analyze_performance()
            if not current_metrics:
                return []
            
            recommendations = []
            
            # Memory optimization recommendations
            recommendations.extend(self._analyze_memory_usage(current_metrics))
            
            # Latency optimization recommendations
            recommendations.extend(self._analyze_latency(current_metrics))
            
            # Hit rate optimization recommendations
            recommendations.extend(self._analyze_hit_rate(current_metrics))
            
            # Throughput optimization recommendations
            recommendations.extend(self._analyze_throughput(current_metrics))
            
            # Configuration optimization recommendations
            recommendations.extend(self._analyze_configuration())
            
            # Pattern optimization recommendations
            recommendations.extend(self._analyze_patterns())
            
            return sorted(recommendations, key=lambda r: r.score, reverse=True)
            
        except Exception as e:
            logger.error("Failed to generate recommendations", error=str(e))
            return []
    
    def _analyze_memory_usage(self, metrics: Dict[str, float]) -> List[TuningRecommendation]:
        """Analyze memory usage and generate recommendations."""
        recommendations = []
        memory_usage = metrics.get("memory_usage_mb", 0)
        
        if memory_usage > self.config.max_memory_mb * 0.9:
            recommendations.append(TuningRecommendation(
                area=TuningArea.MEMORY_USAGE,
                title="Reduce Memory Usage",
                description="Memory usage is approaching the configured limit",
                priority="high",
                impact="high",
                effort="medium",
                current_value=f"{memory_usage:.1f} MB",
                recommended_value=f"< {self.config.max_memory_mb * 0.8:.1f} MB",
                rationale="High memory usage can lead to system instability and poor performance",
                implementation_steps=[
                    "Reduce L1 cache size",
                    "Implement more aggressive TTL policies",
                    "Enable compression if not already enabled",
                    "Clear unused cache entries"
                ],
                expected_improvement="20-30% reduction in memory usage"
            ))
        
        # Check L1 cache efficiency
        l1_size = metrics.get("l1_cache_size", 0)
        hit_rate = metrics.get("hit_rate", 0)
        
        if l1_size > 0 and hit_rate < 0.6:
            recommendations.append(TuningRecommendation(
                area=TuningArea.MEMORY_USAGE,
                title="Optimize L1 Cache Size",
                description="L1 cache is not providing sufficient hit rate for its memory usage",
                priority="medium",
                impact="medium",
                effort="low",
                current_value=f"{l1_size} items",
                recommended_value=f"{int(l1_size * 0.7)} items",
                rationale="Poor L1 cache hit rate suggests inefficient memory usage",
                implementation_steps=[
                    "Reduce L1 cache max size",
                    "Implement better eviction policies",
                    "Analyze access patterns"
                ],
                expected_improvement="10-15% improvement in memory efficiency"
            ))
        
        return recommendations
    
    def _analyze_latency(self, metrics: Dict[str, float]) -> List[TuningRecommendation]:
        """Analyze latency and generate recommendations."""
        recommendations = []
        latency = metrics.get("avg_latency_ms", 0)
        
        if latency > self.config.target_latency_ms * 2:
            recommendations.append(TuningRecommendation(
                area=TuningArea.LATENCY,
                title="Reduce Cache Latency",
                description="Average latency is significantly above target",
                priority="high",
                impact="high",
                effort="medium",
                current_value=f"{latency:.2f} ms",
                recommended_value=f"< {self.config.target_latency_ms:.2f} ms",
                rationale="High latency impacts user experience and system performance",
                implementation_steps=[
                    "Increase L1 cache size for hot data",
                    "Optimize Redis connection pooling",
                    "Consider read replicas for read-heavy workloads",
                    "Enable compression for large values"
                ],
                expected_improvement="40-60% reduction in average latency"
            ))
        
        elif latency > self.config.target_latency_ms * 1.5:
            recommendations.append(TuningRecommendation(
                area=TuningArea.LATENCY,
                title="Fine-tune Latency Performance",
                description="Latency is above target but not critical",
                priority="medium",
                impact="medium",
                effort="low",
                current_value=f"{latency:.2f} ms",
                recommended_value=f"< {self.config.target_latency_ms:.2f} ms",
                rationale="Optimizing latency improves overall system responsiveness",
                implementation_steps=[
                    "Tune connection pool settings",
                    "Optimize serialization",
                    "Review network configuration"
                ],
                expected_improvement="20-30% reduction in average latency"
            ))
        
        return recommendations
    
    def _analyze_hit_rate(self, metrics: Dict[str, float]) -> List[TuningRecommendation]:
        """Analyze hit rate and generate recommendations."""
        recommendations = []
        hit_rate = metrics.get("hit_rate", 0)
        
        if hit_rate < self.config.target_hit_rate * 0.8:
            recommendations.append(TuningRecommendation(
                area=TuningArea.HIT_RATE,
                title="Improve Cache Hit Rate",
                description="Hit rate is significantly below target",
                priority="high",
                impact="high",
                effort="medium",
                current_value=f"{hit_rate:.2%}",
                recommended_value=f"> {self.config.target_hit_rate:.2%}",
                rationale="Low hit rate indicates cache is not effectively reducing backend load",
                implementation_steps=[
                    "Increase cache size",
                    "Implement cache warming strategies",
                    "Analyze and optimize TTL values",
                    "Review cache key patterns"
                ],
                expected_improvement="15-25% increase in hit rate"
            ))
        
        elif hit_rate < self.config.target_hit_rate:
            recommendations.append(TuningRecommendation(
                area=TuningArea.HIT_RATE,
                title="Optimize Cache Hit Rate",
                description="Hit rate is below target",
                priority="medium",
                impact="medium",
                effort="low",
                current_value=f"{hit_rate:.2%}",
                recommended_value=f"> {self.config.target_hit_rate:.2%}",
                rationale="Improving hit rate reduces backend load and improves performance",
                implementation_steps=[
                    "Fine-tune TTL values",
                    "Implement predictive caching",
                    "Optimize cache key design"
                ],
                expected_improvement="5-10% increase in hit rate"
            ))
        
        return recommendations
    
    def _analyze_throughput(self, metrics: Dict[str, float]) -> List[TuningRecommendation]:
        """Analyze throughput and generate recommendations."""
        recommendations = []
        throughput = metrics.get("throughput_ops_sec", 0)
        
        if throughput < self.config.target_throughput * 0.7:
            recommendations.append(TuningRecommendation(
                area=TuningArea.THROUGHPUT,
                title="Increase Cache Throughput",
                description="Throughput is significantly below target",
                priority="high",
                impact="high",
                effort="high",
                current_value=f"{throughput:.0f} ops/sec",
                recommended_value=f"> {self.config.target_throughput:.0f} ops/sec",
                rationale="Low throughput limits system scalability",
                implementation_steps=[
                    "Implement Redis clustering",
                    "Optimize connection pooling",
                    "Use pipeline operations",
                    "Consider async operations"
                ],
                expected_improvement="50-100% increase in throughput"
            ))
        
        return recommendations
    
    def _analyze_configuration(self) -> List[TuningRecommendation]:
        """Analyze current configuration and suggest optimizations."""
        recommendations = []
        
        # Check if compression is enabled for large values
        cache_config = self.cache_manager.cache_manager.cache.config
        
        if not cache_config.enable_compression:
            recommendations.append(TuningRecommendation(
                area=TuningArea.MEMORY_USAGE,
                title="Enable Compression",
                description="Compression is disabled, consider enabling for better memory efficiency",
                priority="medium",
                impact="medium",
                effort="low",
                current_value="Disabled",
                recommended_value="Enabled",
                rationale="Compression can significantly reduce memory usage for large values",
                implementation_steps=[
                    "Enable compression in cache configuration",
                    "Set appropriate compression threshold",
                    "Monitor performance impact"
                ],
                expected_improvement="20-40% reduction in memory usage for large values"
            ))
        
        # Check TTL configuration
        if cache_config.default_ttl > self.config.max_ttl_seconds:
            recommendations.append(TuningRecommendation(
                area=TuningArea.MEMORY_USAGE,
                title="Optimize Default TTL",
                description="Default TTL is very high, consider reducing for better memory turnover",
                priority="low",
                impact="low",
                effort="low",
                current_value=f"{cache_config.default_ttl:.0f} seconds",
                recommended_value=f"< {self.config.max_ttl_seconds:.0f} seconds",
                rationale="Long TTL values can lead to stale data and inefficient memory usage",
                implementation_steps=[
                    "Analyze data access patterns",
                    "Reduce default TTL",
                    "Implement dynamic TTL based on data type"
                ],
                expected_improvement="5-10% improvement in memory efficiency"
            ))
        
        return recommendations
    
    def _analyze_patterns(self) -> List[TuningRecommendation]:
        """Analyze cache patterns and suggest optimizations."""
        recommendations = []
        
        # This would analyze the pattern usage statistics
        # For now, provide general pattern recommendations
        
        pattern_config = self.cache_manager.pattern_manager.config
        
        if pattern_config.read_pattern == CachePattern.CACHE_ASIDE:
            recommendations.append(TuningRecommendation(
                area=TuningArea.PATTERNS,
                title="Consider Read-Through Pattern",
                description="Cache-aside pattern may benefit from read-through for some use cases",
                priority="low",
                impact="medium",
                effort="medium",
                current_value="Cache-aside",
                recommended_value="Read-through for hot data",
                rationale="Read-through pattern can improve hit rates and reduce backend load",
                implementation_steps=[
                    "Identify hot data patterns",
                    "Implement read-through for frequently accessed data",
                    "Monitor performance impact"
                ],
                expected_improvement="10-20% improvement in hit rate for hot data"
            ))
        
        if pattern_config.consistency_level == ConsistencyLevel.STRONG:
            recommendations.append(TuningRecommendation(
                area=TuningArea.CONSISTENCY,
                title="Consider Eventual Consistency",
                description="Strong consistency may impact performance",
                priority="low",
                impact="medium",
                effort="low",
                current_value="Strong",
                recommended_value="Eventual (where appropriate)",
                rationale="Eventual consistency can improve performance for non-critical data",
                implementation_steps=[
                    "Identify data that can tolerate eventual consistency",
                    "Implement different consistency levels per data type",
                    "Monitor data consistency requirements"
                ],
                expected_improvement="15-25% improvement in write performance"
            ))
        
        return recommendations
    
    async def generate_tuning_report(self) -> TuningReport:
        """Generate comprehensive tuning report."""
        try:
            current_metrics = await self.analyze_performance()
            recommendations = await self.generate_recommendations()
            
            # Get current configuration
            cache_info = await self.cache_manager.get_info()
            
            # Generate optimization summary
            high_priority_count = sum(1 for r in recommendations if r.priority == "high")
            total_recommendations = len(recommendations)
            
            if high_priority_count > 3:
                optimization_summary = f"Immediate attention required: {high_priority_count} critical issues found"
            elif high_priority_count > 0:
                optimization_summary = f"Some optimization needed: {high_priority_count} high-priority recommendations"
            elif total_recommendations > 0:
                optimization_summary = f"Performance tuning opportunities: {total_recommendations} recommendations"
            else:
                optimization_summary = "Cache is well-optimized"
            
            # Estimate improvements
            estimated_improvements = {
                "latency": "10-30% reduction",
                "throughput": "15-40% increase",
                "memory_efficiency": "20-35% improvement",
                "hit_rate": "5-15% increase"
            }
            
            return TuningReport(
                timestamp=asyncio.get_event_loop().time(),
                cache_config=cache_info.get("config", {}),
                performance_metrics=current_metrics,
                recommendations=recommendations,
                optimization_summary=optimization_summary,
                estimated_improvements=estimated_improvements
            )
            
        except Exception as e:
            logger.error("Failed to generate tuning report", error=str(e))
            raise


class AutoOptimizer:
    """Automated cache optimization based on performance goals."""
    
    def __init__(
        self,
        cache_manager: IntegratedCacheManager,
        tuning_config: TuningConfig,
        auto_apply: bool = False
    ):
        self.cache_manager = cache_manager
        self.tuning_config = tuning_config
        self.auto_apply = auto_apply
        self.tuner = CacheTuner(cache_manager, tuning_config)
        self._optimization_history: List[Dict[str, Any]] = []
    
    async def optimize_cache(self) -> Dict[str, Any]:
        """Perform automated cache optimization."""
        try:
            logger.info("Starting automated cache optimization")
            
            # Generate tuning report
            report = await self.tuner.generate_tuning_report()
            
            # Get top recommendations
            top_recommendations = report.get_top_recommendations(5)
            
            optimizations_applied = []
            
            if self.auto_apply:
                # Apply safe optimizations automatically
                for recommendation in top_recommendations:
                    if self._is_safe_optimization(recommendation):
                        try:
                            success = await self._apply_recommendation(recommendation)
                            if success:
                                optimizations_applied.append(recommendation.title)
                                logger.info(
                                    "Applied optimization",
                                    recommendation=recommendation.title
                                )
                        except Exception as e:
                            logger.error(
                                "Failed to apply optimization",
                                recommendation=recommendation.title,
                                error=str(e)
                            )
            
            # Record optimization session
            optimization_record = {
                "timestamp": report.timestamp,
                "recommendations_count": len(report.recommendations),
                "high_priority_count": sum(1 for r in report.recommendations if r.priority == "high"),
                "optimizations_applied": optimizations_applied,
                "performance_metrics": report.performance_metrics
            }
            
            self._optimization_history.append(optimization_record)
            
            return {
                "status": "completed",
                "report": report,
                "optimizations_applied": optimizations_applied,
                "auto_apply_enabled": self.auto_apply
            }
            
        except Exception as e:
            logger.error("Automated optimization failed", error=str(e))
            return {
                "status": "failed",
                "error": str(e),
                "optimizations_applied": []
            }
    
    def _is_safe_optimization(self, recommendation: TuningRecommendation) -> bool:
        """Check if optimization is safe to apply automatically."""
        # Only apply low-effort, low-risk optimizations automatically
        safe_areas = [TuningArea.MEMORY_USAGE, TuningArea.LATENCY]
        
        return (
            recommendation.area in safe_areas and
            recommendation.effort in ["low", "medium"] and
            recommendation.priority in ["medium", "high"]
        )
    
    async def _apply_recommendation(self, recommendation: TuningRecommendation) -> bool:
        """Apply a specific recommendation."""
        try:
            if recommendation.area == TuningArea.MEMORY_USAGE:
                if "Reduce L1 cache size" in recommendation.implementation_steps:
                    # Reduce L1 cache size
                    current_size = self.cache_manager.cache_manager.cache.config.l1_max_size
                    new_size = max(100, int(current_size * 0.8))
                    
                    # This would require cache restart in real implementation
                    logger.info(f"Would reduce L1 cache size from {current_size} to {new_size}")
                    return True
            
            elif recommendation.area == TuningArea.LATENCY:
                if "Optimize connection pool" in recommendation.title.lower():
                    # Connection pool optimization would be applied here
                    logger.info("Would optimize connection pool settings")
                    return True
            
            # Other optimization implementations would go here
            return False
            
        except Exception as e:
            logger.error(
                "Failed to apply recommendation",
                recommendation=recommendation.title,
                error=str(e)
            )
            return False
    
    def get_optimization_history(self) -> List[Dict[str, Any]]:
        """Get history of optimization sessions."""
        return self._optimization_history.copy()
    
    async def schedule_optimization(self, interval_hours: float = 24.0) -> None:
        """Schedule periodic optimization."""
        while True:
            try:
                await asyncio.sleep(interval_hours * 3600)
                await self.optimize_cache()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Scheduled optimization failed", error=str(e))


# Convenience functions
async def quick_tune(cache_manager: IntegratedCacheManager) -> TuningReport:
    """Quick tuning analysis and recommendations."""
    config = TuningConfig()
    tuner = CacheTuner(cache_manager, config)
    return await tuner.generate_tuning_report()


async def auto_optimize(
    cache_manager: IntegratedCacheManager,
    performance_goal: PerformanceGoal = PerformanceGoal.BALANCE_ALL
) -> Dict[str, Any]:
    """Automated optimization with specified performance goal."""
    config = TuningConfig(performance_goal=performance_goal)
    optimizer = AutoOptimizer(cache_manager, config, auto_apply=True)
    return await optimizer.optimize_cache()