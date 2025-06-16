"""
Quality MCP Server - Python Learning Layer
Provides ML-based learning capabilities for test optimization and quality prediction
"""

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingRegressor
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, mean_squared_error
import joblib

logger = logging.getLogger(__name__)


class ModelType(Enum):
    TEST_FAILURE_PREDICTOR = "test_failure_predictor"
    COVERAGE_OPTIMIZER = "coverage_optimizer"
    PERFORMANCE_ANALYZER = "performance_analyzer"
    QUALITY_CLASSIFIER = "quality_classifier"


@dataclass
class TestExecutionData:
    test_name: str
    file_changes: List[str]
    complexity_delta: float
    previous_failures: int
    coverage_impact: float
    execution_time: float
    passed: bool
    timestamp: datetime


@dataclass
class CoverageData:
    file_path: str
    current_coverage: float
    uncovered_lines: int
    branch_coverage: float
    complexity: float
    test_count: int
    change_frequency: float


@dataclass
class PerformanceData:
    function_name: str
    algorithm_complexity: float
    data_size: int
    memory_allocations: int
    io_operations: int
    cpu_usage: float
    execution_time: float


@dataclass
class QualityData:
    file_path: str
    cyclomatic_complexity: float
    cognitive_complexity: float
    code_duplication: float
    test_coverage: float
    documentation_coverage: float
    quality_score: float


class QualityLearning:
    """Main learning system for quality MCP server"""
    
    def __init__(self, model_dir: Path = Path("./models")):
        self.model_dir = model_dir
        self.model_dir.mkdir(exist_ok=True)
        
        self.models: Dict[ModelType, Any] = {}
        self.scalers: Dict[ModelType, StandardScaler] = {}
        self.feature_importance: Dict[str, float] = {}
        
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize ML models for each prediction task"""
        # Test failure predictor - Random Forest for classification
        self.models[ModelType.TEST_FAILURE_PREDICTOR] = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        # Coverage optimizer - Gradient Boosting for regression
        self.models[ModelType.COVERAGE_OPTIMIZER] = GradientBoostingRegressor(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=5,
            random_state=42
        )
        
        # Performance analyzer - Gradient Boosting for regression
        self.models[ModelType.PERFORMANCE_ANALYZER] = GradientBoostingRegressor(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=5,
            random_state=42
        )
        
        # Quality classifier - Random Forest for multi-class classification
        self.models[ModelType.QUALITY_CLASSIFIER] = RandomForestClassifier(
            n_estimators=150,
            max_depth=15,
            random_state=42
        )
        
        # Initialize scalers
        for model_type in ModelType:
            self.scalers[model_type] = StandardScaler()
    
    async def learn_test_patterns(self, execution_data: List[TestExecutionData]) -> Dict[str, Any]:
        """Learn patterns from test execution history"""
        if not execution_data:
            return {"error": "No execution data provided"}
        
        # Extract features
        features = []
        labels = []
        
        for data in execution_data:
            feature_vector = [
                len(data.file_changes),
                data.complexity_delta,
                data.previous_failures,
                data.coverage_impact,
                data.execution_time,
                data.timestamp.timestamp() % (24 * 3600),  # Time of day
            ]
            features.append(feature_vector)
            labels.append(1 if data.passed else 0)
        
        X = np.array(features)
        y = np.array(labels)
        
        # Scale features
        X_scaled = self.scalers[ModelType.TEST_FAILURE_PREDICTOR].fit_transform(X)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42
        )
        
        # Train model
        model = self.models[ModelType.TEST_FAILURE_PREDICTOR]
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        # Extract feature importance
        feature_names = [
            "file_changes_count",
            "complexity_delta",
            "previous_failures",
            "coverage_impact",
            "execution_time",
            "time_of_day"
        ]
        
        importance = dict(zip(feature_names, model.feature_importances_))
        self.feature_importance.update(importance)
        
        # Save model
        self._save_model(ModelType.TEST_FAILURE_PREDICTOR)
        
        return {
            "accuracy": accuracy,
            "feature_importance": importance,
            "samples_trained": len(X_train),
            "test_failure_rate": 1 - (y.sum() / len(y))
        }
    
    async def predict_test_failures(self, test_changes: List[Dict[str, Any]]) -> List[Dict[str, float]]:
        """Predict which tests are likely to fail"""
        model = self._load_model(ModelType.TEST_FAILURE_PREDICTOR)
        if model is None:
            return []
        
        predictions = []
        
        for change in test_changes:
            feature_vector = [
                len(change.get("file_changes", [])),
                change.get("complexity_delta", 0),
                change.get("previous_failures", 0),
                change.get("coverage_impact", 0),
                change.get("execution_time", 1),
                datetime.now().timestamp() % (24 * 3600),
            ]
            
            X = np.array([feature_vector])
            X_scaled = self.scalers[ModelType.TEST_FAILURE_PREDICTOR].transform(X)
            
            # Get probability of failure
            prob = model.predict_proba(X_scaled)[0]
            failure_prob = 1 - prob[1] if len(prob) > 1 else 0.5
            
            predictions.append({
                "test_name": change.get("test_name", "unknown"),
                "failure_probability": float(failure_prob),
                "confidence": float(max(prob))
            })
        
        # Sort by failure probability
        predictions.sort(key=lambda x: x["failure_probability"], reverse=True)
        
        return predictions
    
    async def optimize_coverage(self, coverage_data: List[CoverageData]) -> Dict[str, Any]:
        """Learn coverage optimization patterns"""
        if not coverage_data:
            return {"error": "No coverage data provided"}
        
        features = []
        targets = []
        
        for data in coverage_data:
            feature_vector = [
                data.current_coverage,
                data.uncovered_lines,
                data.branch_coverage,
                data.complexity,
                data.test_count,
                data.change_frequency
            ]
            features.append(feature_vector)
            # Target is the potential coverage improvement
            targets.append(1.0 - data.current_coverage)
        
        X = np.array(features)
        y = np.array(targets)
        
        # Scale features
        X_scaled = self.scalers[ModelType.COVERAGE_OPTIMIZER].fit_transform(X)
        
        # Train model
        model = self.models[ModelType.COVERAGE_OPTIMIZER]
        model.fit(X_scaled, y)
        
        # Predict coverage gaps
        predictions = model.predict(X_scaled)
        mse = mean_squared_error(y, predictions)
        
        # Save model
        self._save_model(ModelType.COVERAGE_OPTIMIZER)
        
        return {
            "mse": mse,
            "avg_coverage_gap": y.mean(),
            "files_analyzed": len(coverage_data),
            "optimization_potential": predictions.mean()
        }
    
    async def analyze_performance_patterns(self, perf_data: List[PerformanceData]) -> Dict[str, Any]:
        """Learn performance patterns and predict bottlenecks"""
        if not perf_data:
            return {"error": "No performance data provided"}
        
        features = []
        targets = []
        
        for data in perf_data:
            feature_vector = [
                data.algorithm_complexity,
                np.log1p(data.data_size),
                data.memory_allocations,
                data.io_operations,
                data.cpu_usage
            ]
            features.append(feature_vector)
            targets.append(data.execution_time)
        
        X = np.array(features)
        y = np.array(targets)
        
        # Scale features
        X_scaled = self.scalers[ModelType.PERFORMANCE_ANALYZER].fit_transform(X)
        
        # Train model
        model = self.models[ModelType.PERFORMANCE_ANALYZER]
        model.fit(X_scaled, y)
        
        # Analyze bottlenecks
        feature_names = [
            "algorithm_complexity",
            "data_size_log",
            "memory_allocations",
            "io_operations",
            "cpu_usage"
        ]
        
        importance = dict(zip(feature_names, model.feature_importances_))
        
        # Identify performance bottlenecks
        bottlenecks = []
        threshold = np.percentile(y, 90)  # Top 10% slowest
        
        for i, time in enumerate(y):
            if time > threshold:
                bottleneck_features = X[i]
                main_bottleneck = feature_names[np.argmax(bottleneck_features)]
                bottlenecks.append({
                    "function": perf_data[i].function_name,
                    "execution_time": time,
                    "main_bottleneck": main_bottleneck
                })
        
        # Save model
        self._save_model(ModelType.PERFORMANCE_ANALYZER)
        
        return {
            "feature_importance": importance,
            "bottlenecks": bottlenecks[:10],  # Top 10 bottlenecks
            "avg_execution_time": y.mean(),
            "performance_threshold": threshold
        }
    
    async def classify_code_quality(self, quality_data: List[QualityData]) -> Dict[str, Any]:
        """Classify code quality and identify improvement areas"""
        if not quality_data:
            return {"error": "No quality data provided"}
        
        features = []
        labels = []
        
        for data in quality_data:
            feature_vector = [
                data.cyclomatic_complexity,
                data.cognitive_complexity,
                data.code_duplication,
                data.test_coverage,
                data.documentation_coverage
            ]
            features.append(feature_vector)
            
            # Classify quality into categories
            if data.quality_score >= 0.9:
                label = 4  # Excellent
            elif data.quality_score >= 0.8:
                label = 3  # Good
            elif data.quality_score >= 0.7:
                label = 2  # Fair
            elif data.quality_score >= 0.6:
                label = 1  # Poor
            else:
                label = 0  # Critical
            
            labels.append(label)
        
        X = np.array(features)
        y = np.array(labels)
        
        # Scale features
        X_scaled = self.scalers[ModelType.QUALITY_CLASSIFIER].fit_transform(X)
        
        # Train model
        model = self.models[ModelType.QUALITY_CLASSIFIER]
        model.fit(X_scaled, y)
        
        # Analyze quality distribution
        quality_distribution = {
            "excellent": (y == 4).sum(),
            "good": (y == 3).sum(),
            "fair": (y == 2).sum(),
            "poor": (y == 1).sum(),
            "critical": (y == 0).sum()
        }
        
        # Identify improvement areas
        feature_names = [
            "cyclomatic_complexity",
            "cognitive_complexity",
            "code_duplication",
            "test_coverage",
            "documentation_coverage"
        ]
        
        importance = dict(zip(feature_names, model.feature_importances_))
        
        # Save model
        self._save_model(ModelType.QUALITY_CLASSIFIER)
        
        return {
            "quality_distribution": quality_distribution,
            "feature_importance": importance,
            "files_analyzed": len(quality_data),
            "avg_quality_score": sum(d.quality_score for d in quality_data) / len(quality_data)
        }
    
    def smart_test_selection(self, code_changes: Dict[str, Any]) -> List[str]:
        """ML-based test selection based on code changes"""
        # Load test failure predictor
        model = self._load_model(ModelType.TEST_FAILURE_PREDICTOR)
        if model is None:
            return []
        
        # Analyze impact of changes
        impact_scores = {}
        
        for file, changes in code_changes.items():
            # Calculate impact score based on:
            # - Number of changes
            # - Complexity of changed code
            # - Historical failure rate
            # - Dependencies
            
            impact_score = (
                len(changes.get("additions", [])) * 0.3 +
                len(changes.get("deletions", [])) * 0.2 +
                len(changes.get("modifications", [])) * 0.5
            )
            
            impact_scores[file] = impact_score
        
        # Select tests based on impact
        selected_tests = []
        
        # This would be enhanced with actual test mapping
        for file, score in sorted(impact_scores.items(), key=lambda x: x[1], reverse=True):
            # Map files to tests (simplified)
            test_file = file.replace("src/", "tests/test_").replace(".py", "_test.py")
            selected_tests.append(test_file)
        
        return selected_tests[:20]  # Return top 20 most relevant tests
    
    def _save_model(self, model_type: ModelType):
        """Save model and scaler to disk"""
        model_path = self.model_dir / f"{model_type.value}_model.joblib"
        scaler_path = self.model_dir / f"{model_type.value}_scaler.joblib"
        
        joblib.dump(self.models[model_type], model_path)
        joblib.dump(self.scalers[model_type], scaler_path)
        
        logger.info(f"Saved {model_type.value} model to {model_path}")
    
    def _load_model(self, model_type: ModelType):
        """Load model from disk"""
        model_path = self.model_dir / f"{model_type.value}_model.joblib"
        scaler_path = self.model_dir / f"{model_type.value}_scaler.joblib"
        
        if model_path.exists() and scaler_path.exists():
            self.models[model_type] = joblib.load(model_path)
            self.scalers[model_type] = joblib.load(scaler_path)
            logger.info(f"Loaded {model_type.value} model from {model_path}")
            return self.models[model_type]
        
        return None


class TestFailurePredictor:
    """Specialized predictor for test failures"""
    
    def __init__(self, learning_system: QualityLearning):
        self.learning_system = learning_system
        self.failure_history: Dict[str, List[bool]] = {}
    
    async def analyze_failures(self, test_results: Dict[str, Any]) -> Dict[str, float]:
        """Analyze test failure patterns"""
        failure_patterns = {}
        
        for test_name, results in test_results.items():
            # Track failure history
            if test_name not in self.failure_history:
                self.failure_history[test_name] = []
            
            self.failure_history[test_name].extend(results.get("passed", []))
            
            # Calculate failure rate
            history = self.failure_history[test_name][-100:]  # Last 100 runs
            failure_rate = 1 - (sum(history) / len(history)) if history else 0
            
            # Detect flakiness
            flakiness = self._calculate_flakiness(history)
            
            failure_patterns[test_name] = {
                "failure_rate": failure_rate,
                "flakiness": flakiness,
                "trend": self._calculate_trend(history)
            }
        
        return failure_patterns
    
    def _calculate_flakiness(self, history: List[bool]) -> float:
        """Calculate test flakiness score"""
        if len(history) < 2:
            return 0.0
        
        # Count status changes
        changes = sum(1 for i in range(1, len(history)) if history[i] != history[i-1])
        return changes / (len(history) - 1)
    
    def _calculate_trend(self, history: List[bool]) -> str:
        """Calculate failure trend"""
        if len(history) < 10:
            return "insufficient_data"
        
        recent = history[-10:]
        older = history[-20:-10] if len(history) >= 20 else history[:-10]
        
        recent_rate = 1 - (sum(recent) / len(recent))
        older_rate = 1 - (sum(older) / len(older))
        
        if recent_rate > older_rate + 0.1:
            return "worsening"
        elif recent_rate < older_rate - 0.1:
            return "improving"
        else:
            return "stable"


class CoverageOptimizer:
    """Optimize test coverage using ML"""
    
    def __init__(self, learning_system: QualityLearning):
        self.learning_system = learning_system
    
    async def find_gaps(self, coverage_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find coverage gaps using ML analysis"""
        gaps = []
        
        for file, coverage in coverage_data.items():
            if coverage["line_coverage"] < 0.8:
                # Analyze uncovered code patterns
                gap_info = {
                    "file": file,
                    "current_coverage": coverage["line_coverage"],
                    "gap_severity": 1 - coverage["line_coverage"],
                    "uncovered_lines": coverage.get("uncovered_lines", []),
                    "priority": self._calculate_priority(coverage)
                }
                
                # Suggest tests to improve coverage
                gap_info["suggested_tests"] = self._suggest_tests(file, coverage)
                
                gaps.append(gap_info)
        
        # Sort by priority
        gaps.sort(key=lambda x: x["priority"], reverse=True)
        
        return gaps
    
    def _calculate_priority(self, coverage: Dict[str, Any]) -> float:
        """Calculate coverage gap priority"""
        # Consider multiple factors
        line_coverage = coverage.get("line_coverage", 0)
        complexity = coverage.get("complexity", 1)
        importance = coverage.get("importance", 1)
        
        # Higher priority for complex, important code with low coverage
        priority = (1 - line_coverage) * complexity * importance
        
        return priority
    
    def _suggest_tests(self, file: str, coverage: Dict[str, Any]) -> List[str]:
        """Suggest tests to improve coverage"""
        suggestions = []
        
        # Analyze uncovered lines
        uncovered = coverage.get("uncovered_lines", [])
        
        # Group uncovered lines into regions
        regions = self._group_uncovered_regions(uncovered)
        
        for region in regions:
            if len(region) > 5:
                suggestions.append(f"Add test for lines {region[0]}-{region[-1]} in {file}")
            else:
                suggestions.append(f"Add test for line {region[0]} in {file}")
        
        return suggestions[:5]  # Top 5 suggestions
    
    def _group_uncovered_regions(self, lines: List[int]) -> List[List[int]]:
        """Group consecutive uncovered lines"""
        if not lines:
            return []
        
        regions = []
        current_region = [lines[0]]
        
        for line in lines[1:]:
            if line == current_region[-1] + 1:
                current_region.append(line)
            else:
                regions.append(current_region)
                current_region = [line]
        
        regions.append(current_region)
        return regions


class PerformanceAnalyzer:
    """Analyze performance patterns using ML"""
    
    def __init__(self, learning_system: QualityLearning):
        self.learning_system = learning_system
    
    async def detect_patterns(self, perf_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect performance patterns and anomalies"""
        patterns = []
        
        # Analyze execution times
        exec_times = perf_data.get("execution_times", {})
        
        # Calculate statistics
        times = list(exec_times.values())
        if times:
            mean_time = np.mean(times)
            std_time = np.std(times)
            threshold = mean_time + 2 * std_time  # 2 standard deviations
            
            # Find outliers
            for func, time in exec_times.items():
                if time > threshold:
                    patterns.append({
                        "type": "performance_outlier",
                        "function": func,
                        "execution_time": time,
                        "severity": (time - mean_time) / std_time,
                        "suggestion": f"Optimize {func} - execution time {time:.2f}ms is {(time/mean_time):.1f}x average"
                    })
        
        # Analyze memory usage
        memory_data = perf_data.get("memory_usage", {})
        patterns.extend(self._analyze_memory_patterns(memory_data))
        
        return patterns
    
    def _analyze_memory_patterns(self, memory_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze memory usage patterns"""
        patterns = []
        
        # Look for memory leaks
        allocations = memory_data.get("allocations", {})
        deallocations = memory_data.get("deallocations", {})
        
        for location, alloc_count in allocations.items():
            dealloc_count = deallocations.get(location, 0)
            
            if alloc_count > dealloc_count * 1.1:  # 10% threshold
                patterns.append({
                    "type": "potential_memory_leak",
                    "location": location,
                    "allocations": alloc_count,
                    "deallocations": dealloc_count,
                    "leaked_percentage": ((alloc_count - dealloc_count) / alloc_count) * 100
                })
        
        return patterns


class QualityClassifier:
    """Classify code quality using ML"""
    
    def __init__(self, learning_system: QualityLearning):
        self.learning_system = learning_system
        self.quality_thresholds = {
            "excellent": 0.9,
            "good": 0.8,
            "fair": 0.7,
            "poor": 0.6
        }
    
    async def score(self, code_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Score code quality based on metrics"""
        # Extract metrics
        complexity = code_metrics.get("complexity", 0)
        coverage = code_metrics.get("coverage", 0)
        duplication = code_metrics.get("duplication", 0)
        documentation = code_metrics.get("documentation", 0)
        
        # Calculate weighted score
        weights = {
            "complexity": -0.3,  # Lower is better
            "coverage": 0.3,
            "duplication": -0.2,  # Lower is better
            "documentation": 0.2
        }
        
        # Normalize complexity and duplication
        norm_complexity = 1 - min(complexity / 50, 1)  # 50 is max acceptable
        norm_duplication = 1 - duplication
        
        score = (
            norm_complexity * abs(weights["complexity"]) +
            coverage * weights["coverage"] +
            norm_duplication * abs(weights["duplication"]) +
            documentation * weights["documentation"]
        )
        
        # Determine quality level
        quality_level = "critical"
        for level, threshold in self.quality_thresholds.items():
            if score >= threshold:
                quality_level = level
                break
        
        return {
            "overall_score": score,
            "quality_level": quality_level,
            "metrics": {
                "complexity_score": norm_complexity,
                "coverage_score": coverage,
                "duplication_score": norm_duplication,
                "documentation_score": documentation
            },
            "improvements": self._suggest_improvements(code_metrics, score)
        }
    
    def _suggest_improvements(self, metrics: Dict[str, Any], score: float) -> List[str]:
        """Suggest quality improvements"""
        suggestions = []
        
        if metrics.get("complexity", 0) > 20:
            suggestions.append("Reduce cyclomatic complexity by breaking down complex functions")
        
        if metrics.get("coverage", 0) < 0.8:
            suggestions.append("Increase test coverage to at least 80%")
        
        if metrics.get("duplication", 0) > 0.1:
            suggestions.append("Reduce code duplication by extracting common functionality")
        
        if metrics.get("documentation", 0) < 0.7:
            suggestions.append("Improve documentation coverage for public APIs")
        
        return suggestions


# Example usage
async def main():
    """Example usage of the quality learning system"""
    learning = QualityLearning()
    
    # Example test execution data
    test_data = [
        TestExecutionData(
            test_name="test_user_login",
            file_changes=["auth.py", "user.py"],
            complexity_delta=5.2,
            previous_failures=2,
            coverage_impact=0.85,
            execution_time=1.2,
            passed=True,
            timestamp=datetime.now()
        )
    ]
    
    # Learn from test patterns
    result = await learning.learn_test_patterns(test_data)
    print(f"Test pattern learning result: {result}")
    
    # Predict test failures
    predictions = await learning.predict_test_failures([
        {
            "test_name": "test_user_logout",
            "file_changes": ["auth.py"],
            "complexity_delta": 3.1,
            "previous_failures": 0,
            "coverage_impact": 0.9,
            "execution_time": 0.8
        }
    ])
    print(f"Test failure predictions: {predictions}")


if __name__ == "__main__":
    asyncio.run(main())