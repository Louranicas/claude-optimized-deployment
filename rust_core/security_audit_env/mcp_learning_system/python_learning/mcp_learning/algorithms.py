"""
Machine Learning Algorithms for MCP Learning System

Online learning, pattern recognition, and adaptation algorithms.
"""

import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import IncrementalPCA
from sklearn.cluster import MiniBatchKMeans
from sklearn.ensemble import IsolationForest
import torch
import torch.nn as nn
import torch.optim as optim
from collections import deque
import logging
import pickle

logger = logging.getLogger(__name__)


@dataclass
class LearningMetrics:
    """Metrics for learning algorithms"""
    accuracy: float = 0.0
    loss: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    training_time: float = 0.0
    inference_time: float = 0.0
    sample_count: int = 0


@dataclass
class Pattern:
    """Detected pattern in MCP interactions"""
    pattern_id: str
    pattern_type: str
    frequency: float
    confidence: float
    features: np.ndarray
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Adaptation:
    """Adaptation recommendation"""
    adaptation_id: str
    action_type: str
    parameters: Dict[str, Any]
    expected_improvement: float
    confidence: float
    risk_score: float


class BaseLearner(ABC):
    """Base class for all learning algorithms"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.metrics = LearningMetrics()
        self.is_trained = False
    
    @abstractmethod
    async def train(self, data: np.ndarray, labels: Optional[np.ndarray] = None) -> LearningMetrics:
        """Train the model"""
        pass
    
    @abstractmethod
    async def predict(self, data: np.ndarray) -> np.ndarray:
        """Make predictions"""
        pass
    
    @abstractmethod
    def save(self) -> bytes:
        """Serialize the model"""
        pass
    
    @abstractmethod
    def load(self, data: bytes) -> None:
        """Deserialize the model"""
        pass


class OnlineLearner(BaseLearner):
    """Online learning algorithm for streaming data"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.feature_dim = config.get("feature_dim", 128)
        self.learning_rate = config.get("learning_rate", 0.001)
        self.batch_size = config.get("batch_size", 32)
        self.memory_size = config.get("memory_size", 10000)
        
        # Neural network model
        self.model = self._build_model()
        self.optimizer = optim.Adam(self.model.parameters(), lr=self.learning_rate)
        self.criterion = nn.MSELoss()
        
        # Feature processing
        self.scaler = StandardScaler()
        self.pca = IncrementalPCA(n_components=min(self.feature_dim // 2, 50))
        
        # Experience replay buffer
        self.memory = deque(maxlen=self.memory_size)
        
        # Statistics
        self.total_samples = 0
        self.update_count = 0
    
    def _build_model(self) -> nn.Module:
        """Build the neural network model"""
        return nn.Sequential(
            nn.Linear(self.feature_dim, 256),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, self.feature_dim),
        )
    
    async def train(self, data: np.ndarray, labels: Optional[np.ndarray] = None) -> LearningMetrics:
        """Train the model with online learning"""
        start_time = datetime.utcnow()
        
        # Add to memory
        for i in range(len(data)):
            self.memory.append((data[i], labels[i] if labels is not None else data[i]))
        
        # Update statistics
        self.total_samples += len(data)
        
        # Perform training if we have enough samples
        if len(self.memory) >= self.batch_size:
            # Sample batch from memory
            indices = np.random.choice(len(self.memory), self.batch_size, replace=False)
            batch_data = np.array([self.memory[i][0] for i in indices])
            batch_labels = np.array([self.memory[i][1] for i in indices])
            
            # Preprocess
            if not self.scaler.mean_ is None:
                batch_data = self.scaler.transform(batch_data)
                if self.pca.n_components_ is not None:
                    batch_data = self.pca.transform(batch_data)
            else:
                batch_data = self.scaler.fit_transform(batch_data)
                if batch_data.shape[1] > 50:
                    batch_data = self.pca.fit_transform(batch_data)
            
            # Convert to tensors
            x = torch.FloatTensor(batch_data)
            y = torch.FloatTensor(batch_labels)
            
            # Training step
            self.model.train()
            self.optimizer.zero_grad()
            outputs = self.model(x)
            loss = self.criterion(outputs, y)
            loss.backward()
            self.optimizer.step()
            
            # Update metrics
            self.metrics.loss = loss.item()
            self.metrics.sample_count = self.total_samples
            self.update_count += 1
            
            # Calculate accuracy (for autoencoder, use reconstruction error)
            with torch.no_grad():
                predictions = self.model(x)
                mse = nn.functional.mse_loss(predictions, y)
                self.metrics.accuracy = 1.0 - min(mse.item(), 1.0)
        
        self.metrics.training_time = (datetime.utcnow() - start_time).total_seconds()
        self.is_trained = True
        
        return self.metrics
    
    async def predict(self, data: np.ndarray) -> np.ndarray:
        """Make predictions with the model"""
        start_time = datetime.utcnow()
        
        if not self.is_trained:
            raise ValueError("Model not trained yet")
        
        # Preprocess
        data = self.scaler.transform(data)
        if self.pca.n_components_ is not None:
            data = self.pca.transform(data)
        
        # Predict
        self.model.eval()
        with torch.no_grad():
            x = torch.FloatTensor(data)
            predictions = self.model(x).numpy()
        
        self.metrics.inference_time = (datetime.utcnow() - start_time).total_seconds()
        
        return predictions
    
    def save(self) -> bytes:
        """Serialize the model"""
        state = {
            "model_state": self.model.state_dict(),
            "optimizer_state": self.optimizer.state_dict(),
            "scaler": self.scaler,
            "pca": self.pca,
            "metrics": self.metrics,
            "config": self.config,
            "total_samples": self.total_samples,
            "update_count": self.update_count,
        }
        return pickle.dumps(state)
    
    def load(self, data: bytes) -> None:
        """Deserialize the model"""
        state = pickle.loads(data)
        self.model.load_state_dict(state["model_state"])
        self.optimizer.load_state_dict(state["optimizer_state"])
        self.scaler = state["scaler"]
        self.pca = state["pca"]
        self.metrics = state["metrics"]
        self.config = state["config"]
        self.total_samples = state["total_samples"]
        self.update_count = state["update_count"]
        self.is_trained = True


class PatternRecognizer:
    """Pattern recognition for MCP interactions"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.n_clusters = config.get("n_clusters", 10)
        self.anomaly_threshold = config.get("anomaly_threshold", 0.1)
        self.window_size = config.get("window_size", 1000)
        
        # Clustering for pattern detection
        self.clusterer = MiniBatchKMeans(
            n_clusters=self.n_clusters,
            batch_size=100,
            n_init=3
        )
        
        # Anomaly detection
        self.anomaly_detector = IsolationForest(
            contamination=self.anomaly_threshold,
            random_state=42
        )
        
        # Pattern storage
        self.patterns: List[Pattern] = []
        self.pattern_history = deque(maxlen=self.window_size)
        
        # Statistics
        self.total_sequences = 0
        self.anomaly_count = 0
    
    async def analyze_sequence(self, sequence: np.ndarray) -> List[Pattern]:
        """Analyze a sequence of MCP interactions"""
        self.total_sequences += 1
        
        # Update clustering
        if len(sequence) > 0:
            clusters = self.clusterer.fit_predict(sequence)
            
            # Count cluster frequencies
            unique, counts = np.unique(clusters, return_counts=True)
            frequencies = dict(zip(unique, counts / len(clusters)))
            
            # Detect patterns
            new_patterns = []
            for cluster_id, frequency in frequencies.items():
                if frequency > 0.05:  # Significant pattern
                    pattern = Pattern(
                        pattern_id=f"cluster_{cluster_id}_{self.total_sequences}",
                        pattern_type="frequency",
                        frequency=frequency,
                        confidence=min(frequency * 2, 1.0),
                        features=self.clusterer.cluster_centers_[cluster_id],
                        metadata={
                            "cluster_size": counts[cluster_id],
                            "sequence_id": self.total_sequences
                        }
                    )
                    new_patterns.append(pattern)
                    self.patterns.append(pattern)
            
            # Update history
            self.pattern_history.extend(clusters)
            
            # Detect anomalies
            if len(self.pattern_history) > 100:
                history_array = np.array(list(self.pattern_history)).reshape(-1, 1)
                anomalies = self.anomaly_detector.fit_predict(history_array)
                self.anomaly_count += np.sum(anomalies == -1)
            
            return new_patterns
        
        return []
    
    async def detect_anomalies(self, data: np.ndarray) -> Tuple[np.ndarray, float]:
        """Detect anomalies in the data"""
        if len(data) == 0:
            return np.array([]), 0.0
        
        # Fit and predict anomalies
        anomalies = self.anomaly_detector.fit_predict(data)
        anomaly_score = np.mean(anomalies == -1)
        
        return anomalies, anomaly_score
    
    def get_pattern_summary(self) -> Dict[str, Any]:
        """Get summary of detected patterns"""
        if not self.patterns:
            return {"pattern_count": 0, "anomaly_rate": 0.0}
        
        pattern_types = {}
        for pattern in self.patterns:
            if pattern.pattern_type not in pattern_types:
                pattern_types[pattern.pattern_type] = 0
            pattern_types[pattern.pattern_type] += 1
        
        return {
            "pattern_count": len(self.patterns),
            "pattern_types": pattern_types,
            "average_confidence": np.mean([p.confidence for p in self.patterns]),
            "anomaly_rate": self.anomaly_count / max(self.total_sequences, 1),
            "total_sequences": self.total_sequences
        }


class AdaptationEngine:
    """Generate adaptations based on learning"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.adaptation_threshold = config.get("adaptation_threshold", 0.7)
        self.risk_tolerance = config.get("risk_tolerance", 0.3)
        self.history_size = config.get("history_size", 1000)
        
        # Adaptation history
        self.adaptation_history: List[Adaptation] = []
        self.performance_history = deque(maxlen=self.history_size)
        
        # Policy parameters
        self.current_policy = self._default_policy()
        self.policy_performance = {}
    
    def _default_policy(self) -> Dict[str, Any]:
        """Get default policy parameters"""
        return {
            "timeout": 30.0,
            "retry_count": 3,
            "batch_size": 100,
            "cache_ttl": 3600,
            "rate_limit": 1000,
            "priority_weights": {"high": 1.0, "medium": 0.5, "low": 0.1}
        }
    
    async def generate_adaptations(
        self,
        patterns: List[Pattern],
        metrics: Dict[str, float]
    ) -> List[Adaptation]:
        """Generate adaptation recommendations"""
        adaptations = []
        
        # Analyze patterns for adaptation opportunities
        for pattern in patterns:
            if pattern.confidence > self.adaptation_threshold:
                # Generate adaptation based on pattern type
                if pattern.pattern_type == "frequency":
                    adaptation = await self._adapt_for_frequency(pattern, metrics)
                elif pattern.pattern_type == "anomaly":
                    adaptation = await self._adapt_for_anomaly(pattern, metrics)
                else:
                    adaptation = await self._generic_adaptation(pattern, metrics)
                
                if adaptation and adaptation.risk_score < self.risk_tolerance:
                    adaptations.append(adaptation)
                    self.adaptation_history.append(adaptation)
        
        # Update performance history
        if "performance_score" in metrics:
            self.performance_history.append(metrics["performance_score"])
        
        return adaptations
    
    async def _adapt_for_frequency(
        self,
        pattern: Pattern,
        metrics: Dict[str, float]
    ) -> Optional[Adaptation]:
        """Generate adaptation for frequency patterns"""
        # High frequency pattern - optimize for throughput
        if pattern.frequency > 0.3:
            new_batch_size = min(
                int(self.current_policy["batch_size"] * 1.5),
                1000
            )
            
            return Adaptation(
                adaptation_id=f"freq_adapt_{datetime.utcnow().timestamp()}",
                action_type="increase_batch_size",
                parameters={"batch_size": new_batch_size},
                expected_improvement=0.2,
                confidence=pattern.confidence,
                risk_score=0.1
            )
        
        return None
    
    async def _adapt_for_anomaly(
        self,
        pattern: Pattern,
        metrics: Dict[str, float]
    ) -> Optional[Adaptation]:
        """Generate adaptation for anomaly patterns"""
        # Anomaly detected - increase monitoring
        return Adaptation(
            adaptation_id=f"anomaly_adapt_{datetime.utcnow().timestamp()}",
            action_type="increase_monitoring",
            parameters={
                "log_level": "DEBUG",
                "metric_interval": 1.0,
                "alert_threshold": 0.8
            },
            expected_improvement=0.1,
            confidence=pattern.confidence,
            risk_score=0.05
        )
    
    async def _generic_adaptation(
        self,
        pattern: Pattern,
        metrics: Dict[str, float]
    ) -> Optional[Adaptation]:
        """Generate generic adaptation"""
        # Analyze performance trend
        if len(self.performance_history) > 10:
            recent_perf = list(self.performance_history)[-10:]
            trend = np.polyfit(range(len(recent_perf)), recent_perf, 1)[0]
            
            if trend < -0.01:  # Declining performance
                return Adaptation(
                    adaptation_id=f"perf_adapt_{datetime.utcnow().timestamp()}",
                    action_type="optimize_performance",
                    parameters={
                        "cache_ttl": int(self.current_policy["cache_ttl"] * 1.2),
                        "timeout": self.current_policy["timeout"] * 0.8
                    },
                    expected_improvement=0.15,
                    confidence=0.7,
                    risk_score=0.2
                )
        
        return None
    
    def apply_adaptation(self, adaptation: Adaptation) -> None:
        """Apply an adaptation to the current policy"""
        for param, value in adaptation.parameters.items():
            if param in self.current_policy:
                old_value = self.current_policy[param]
                self.current_policy[param] = value
                logger.info(
                    f"Applied adaptation: {param} changed from {old_value} to {value}"
                )
    
    def rollback_adaptation(self, adaptation_id: str) -> bool:
        """Rollback a specific adaptation"""
        # Find the adaptation
        adaptation = next(
            (a for a in self.adaptation_history if a.adaptation_id == adaptation_id),
            None
        )
        
        if not adaptation:
            return False
        
        # Revert parameters
        # Note: This is simplified - in production, you'd track the previous values
        self.current_policy = self._default_policy()
        logger.info(f"Rolled back adaptation: {adaptation_id}")
        
        return True
    
    def get_adaptation_summary(self) -> Dict[str, Any]:
        """Get summary of adaptations"""
        if not self.adaptation_history:
            return {
                "total_adaptations": 0,
                "current_policy": self.current_policy
            }
        
        action_types = {}
        for adaptation in self.adaptation_history:
            if adaptation.action_type not in action_types:
                action_types[adaptation.action_type] = 0
            action_types[adaptation.action_type] += 1
        
        return {
            "total_adaptations": len(self.adaptation_history),
            "action_types": action_types,
            "average_confidence": np.mean([a.confidence for a in self.adaptation_history]),
            "average_risk": np.mean([a.risk_score for a in self.adaptation_history]),
            "current_policy": self.current_policy,
            "performance_trend": self._calculate_performance_trend()
        }
    
    def _calculate_performance_trend(self) -> str:
        """Calculate the current performance trend"""
        if len(self.performance_history) < 5:
            return "insufficient_data"
        
        recent = list(self.performance_history)[-10:]
        trend = np.polyfit(range(len(recent)), recent, 1)[0]
        
        if trend > 0.01:
            return "improving"
        elif trend < -0.01:
            return "declining"
        else:
            return "stable"