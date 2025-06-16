"""
Machine Learning algorithms for adaptive MCP behavior
"""

import asyncio
import json
import pickle
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from torch.nn import LSTM, Linear, ReLU, Dropout
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class LearningConfig:
    """Configuration for learning algorithms"""
    sequence_length: int = 20
    hidden_size: int = 128
    num_layers: int = 2
    learning_rate: float = 0.001
    batch_size: int = 32
    update_frequency: int = 100
    anomaly_threshold: float = 0.1
    memory_size: int = 10000
    epsilon: float = 0.1  # Exploration rate
    gamma: float = 0.95  # Discount factor


class CommandEncoder:
    """Encode commands for neural network processing"""
    
    def __init__(self, vocab_size: int = 10000):
        self.vocab_size = vocab_size
        self.word_to_idx: Dict[str, int] = {"<PAD>": 0, "<UNK>": 1}
        self.idx_to_word: Dict[int, str] = {0: "<PAD>", 1: "<UNK>"}
        self.current_idx = 2
        
    def encode(self, command: Dict[str, Any]) -> np.ndarray:
        """Encode command to vector representation"""
        # Extract command features
        cmd_str = json.dumps(command, sort_keys=True)
        tokens = cmd_str.split()
        
        indices = []
        for token in tokens:
            if token not in self.word_to_idx:
                if self.current_idx < self.vocab_size:
                    self.word_to_idx[token] = self.current_idx
                    self.idx_to_word[self.current_idx] = token
                    self.current_idx += 1
                    indices.append(self.word_to_idx[token])
                else:
                    indices.append(1)  # UNK token
            else:
                indices.append(self.word_to_idx[token])
                
        return np.array(indices, dtype=np.int64)
        
    def decode(self, indices: np.ndarray) -> str:
        """Decode vector back to command representation"""
        tokens = [self.idx_to_word.get(idx, "<UNK>") for idx in indices]
        return " ".join(tokens)


class CommandLSTM(nn.Module):
    """LSTM model for command sequence prediction"""
    
    def __init__(self, vocab_size: int, hidden_size: int, num_layers: int):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, hidden_size)
        self.lstm = LSTM(
            hidden_size,
            hidden_size,
            num_layers,
            batch_first=True,
            dropout=0.2
        )
        self.fc = nn.Sequential(
            Linear(hidden_size, hidden_size),
            ReLU(),
            Dropout(0.2),
            Linear(hidden_size, vocab_size)
        )
        
    def forward(self, x, hidden=None):
        embedded = self.embedding(x)
        output, hidden = self.lstm(embedded, hidden)
        return self.fc(output), hidden


class CommandPredictor:
    """Predict next commands based on learned patterns"""
    
    def __init__(self, config: LearningConfig = None):
        self.config = config or LearningConfig()
        self.encoder = CommandEncoder()
        self.model = CommandLSTM(
            self.encoder.vocab_size,
            self.config.hidden_size,
            self.config.num_layers
        )
        self.optimizer = optim.Adam(
            self.model.parameters(),
            lr=self.config.learning_rate
        )
        self.loss_fn = nn.CrossEntropyLoss()
        self.sequence_buffer = deque(maxlen=self.config.sequence_length)
        self.training_data = []
        
    async def predict_next(self, context: List[Dict[str, Any]], top_k: int = 5) -> List[Dict[str, Any]]:
        """Predict next likely commands"""
        if len(context) < 2:
            return []
            
        # Encode context
        encoded_context = [self.encoder.encode(cmd) for cmd in context[-self.config.sequence_length:]]
        
        # Pad sequences
        max_len = max(len(seq) for seq in encoded_context)
        padded = np.zeros((1, len(encoded_context), max_len), dtype=np.int64)
        
        for i, seq in enumerate(encoded_context):
            padded[0, i, :len(seq)] = seq
            
        # Predict
        self.model.eval()
        with torch.no_grad():
            input_tensor = torch.from_numpy(padded)
            output, _ = self.model(input_tensor)
            predictions = output[0, -1, :].topk(top_k)
            
        # Decode predictions
        predicted_commands = []
        for idx in predictions.indices:
            # Reconstruct command from vocabulary
            # This is simplified - in practice, you'd have a more sophisticated decoder
            predicted_commands.append({
                "type": "predicted",
                "confidence": float(predictions.values[predictions.indices == idx]),
                "command_id": int(idx)
            })
            
        return predicted_commands
        
    def learn_from_sequence(self, commands: List[Dict[str, Any]]):
        """Learn from command sequence"""
        if len(commands) < 2:
            return
            
        # Add to training data
        self.training_data.extend(commands)
        
        # Train periodically
        if len(self.training_data) >= self.config.batch_size:
            self._train_batch()
            
    def _train_batch(self):
        """Train model on accumulated data"""
        self.model.train()
        
        # Prepare batch
        batch_size = min(self.config.batch_size, len(self.training_data))
        batch = self.training_data[:batch_size]
        self.training_data = self.training_data[batch_size:]
        
        # Create input/target pairs
        inputs = []
        targets = []
        
        for i in range(len(batch) - 1):
            inputs.append(self.encoder.encode(batch[i]))
            targets.append(self.encoder.encode(batch[i + 1])[0])  # First token as target
            
        if not inputs:
            return
            
        # Convert to tensors
        max_len = max(len(seq) for seq in inputs)
        input_tensor = torch.zeros(len(inputs), max_len, dtype=torch.long)
        target_tensor = torch.tensor(targets, dtype=torch.long)
        
        for i, seq in enumerate(inputs):
            input_tensor[i, :len(seq)] = torch.from_numpy(seq)
            
        # Train step
        self.optimizer.zero_grad()
        output, _ = self.model(input_tensor)
        loss = self.loss_fn(output[:, -1, :], target_tensor)
        loss.backward()
        self.optimizer.step()
        
        logger.info(f"Training loss: {loss.item():.4f}")


class WorkflowOptimizer:
    """Optimize workflows using reinforcement learning"""
    
    def __init__(self, config: LearningConfig = None):
        self.config = config or LearningConfig()
        self.q_table = defaultdict(lambda: defaultdict(float))
        self.workflow_memory = deque(maxlen=self.config.memory_size)
        self.performance_history = deque(maxlen=1000)
        
    def get_optimal_action(self, state: str, actions: List[str]) -> str:
        """Get optimal action using epsilon-greedy strategy"""
        if np.random.random() < self.config.epsilon:
            # Explore
            return np.random.choice(actions)
        else:
            # Exploit
            q_values = {action: self.q_table[state][action] for action in actions}
            if not q_values or all(v == 0 for v in q_values.values()):
                return np.random.choice(actions)
            return max(q_values, key=q_values.get)
            
    def update(self, state: str, action: str, reward: float, next_state: str):
        """Update Q-values based on experience"""
        # Q-learning update
        current_q = self.q_table[state][action]
        max_next_q = max(self.q_table[next_state].values()) if self.q_table[next_state] else 0
        
        new_q = current_q + self.config.learning_rate * (
            reward + self.config.gamma * max_next_q - current_q
        )
        
        self.q_table[state][action] = new_q
        
        # Store experience
        self.workflow_memory.append({
            "state": state,
            "action": action,
            "reward": reward,
            "next_state": next_state,
            "timestamp": datetime.now()
        })
        
    def calculate_reward(self, execution_time: float, success: bool, resource_usage: Dict[str, float]) -> float:
        """Calculate reward based on performance metrics"""
        # Base reward
        reward = 10.0 if success else -10.0
        
        # Time penalty (normalize to seconds)
        time_penalty = -execution_time / 1000.0
        reward += time_penalty
        
        # Resource usage penalty
        cpu_penalty = -resource_usage.get("cpu", 0) / 100.0
        memory_penalty = -resource_usage.get("memory", 0) / 1000.0
        reward += cpu_penalty + memory_penalty
        
        return reward
        
    def get_optimization_suggestions(self) -> List[Dict[str, Any]]:
        """Get workflow optimization suggestions"""
        suggestions = []
        
        # Analyze Q-table for high-value actions
        for state, actions in self.q_table.items():
            best_action = max(actions, key=actions.get) if actions else None
            if best_action and actions[best_action] > 5.0:
                suggestions.append({
                    "state": state,
                    "recommended_action": best_action,
                    "expected_value": actions[best_action],
                    "confidence": min(1.0, actions[best_action] / 10.0)
                })
                
        # Sort by expected value
        suggestions.sort(key=lambda x: x["expected_value"], reverse=True)
        
        return suggestions[:10]  # Top 10 suggestions


class AnomalyDetector:
    """Detect anomalies in command patterns and system behavior"""
    
    def __init__(self, config: LearningConfig = None):
        self.config = config or LearningConfig()
        self.isolation_forest = IsolationForest(
            contamination=self.config.anomaly_threshold,
            random_state=42
        )
        self.scaler = StandardScaler()
        self.feature_history = deque(maxlen=self.config.memory_size)
        self.anomaly_history = deque(maxlen=1000)
        self.is_fitted = False
        
    def extract_features(self, command: Dict[str, Any], metrics: Dict[str, float]) -> np.ndarray:
        """Extract features for anomaly detection"""
        features = []
        
        # Command features
        features.append(len(json.dumps(command)))  # Command size
        features.append(command.get("priority", 0))
        features.append(hash(command.get("type", "")) % 1000)  # Command type hash
        
        # Performance metrics
        features.append(metrics.get("execution_time", 0))
        features.append(metrics.get("cpu_usage", 0))
        features.append(metrics.get("memory_usage", 0))
        features.append(metrics.get("error_rate", 0))
        
        # Time features
        now = datetime.now()
        features.append(now.hour)
        features.append(now.weekday())
        
        return np.array(features)
        
    def detect_anomaly(self, command: Dict[str, Any], metrics: Dict[str, float]) -> Tuple[bool, float]:
        """Detect if command/metrics represent an anomaly"""
        features = self.extract_features(command, metrics).reshape(1, -1)
        
        # Store features for training
        self.feature_history.append(features[0])
        
        # Train or update model if needed
        if len(self.feature_history) >= 100 and not self.is_fitted:
            self._fit_model()
            
        if not self.is_fitted:
            return False, 0.0
            
        # Predict
        features_scaled = self.scaler.transform(features)
        anomaly_score = self.isolation_forest.score_samples(features_scaled)[0]
        is_anomaly = self.isolation_forest.predict(features_scaled)[0] == -1
        
        # Record anomaly
        if is_anomaly:
            self.anomaly_history.append({
                "command": command,
                "metrics": metrics,
                "score": anomaly_score,
                "timestamp": datetime.now()
            })
            
        return is_anomaly, anomaly_score
        
    def _fit_model(self):
        """Fit the anomaly detection model"""
        if len(self.feature_history) < 10:
            return
            
        features = np.array(list(self.feature_history))
        self.scaler.fit(features)
        features_scaled = self.scaler.transform(features)
        self.isolation_forest.fit(features_scaled)
        self.is_fitted = True
        
        logger.info("Anomaly detector fitted with {} samples".format(len(features)))
        
    def get_anomaly_report(self) -> Dict[str, Any]:
        """Generate anomaly detection report"""
        if not self.anomaly_history:
            return {"anomalies_detected": 0, "patterns": []}
            
        # Analyze patterns in anomalies
        anomaly_types = defaultdict(int)
        time_distribution = defaultdict(int)
        
        for anomaly in self.anomaly_history:
            cmd_type = anomaly["command"].get("type", "unknown")
            anomaly_types[cmd_type] += 1
            
            hour = anomaly["timestamp"].hour
            time_distribution[hour] += 1
            
        return {
            "anomalies_detected": len(self.anomaly_history),
            "anomaly_rate": len(self.anomaly_history) / max(1, len(self.feature_history)),
            "top_anomaly_types": dict(sorted(anomaly_types.items(), key=lambda x: x[1], reverse=True)[:5]),
            "time_distribution": dict(time_distribution),
            "recent_anomalies": [
                {
                    "command_type": a["command"].get("type"),
                    "score": a["score"],
                    "timestamp": a["timestamp"].isoformat()
                }
                for a in list(self.anomaly_history)[-10:]
            ]
        }


class LearningEngine:
    """Main learning engine coordinating all ML components"""
    
    def __init__(self, config: LearningConfig = None):
        self.config = config or LearningConfig()
        self.predictor = CommandPredictor(config)
        self.optimizer = WorkflowOptimizer(config)
        self.anomaly_detector = AnomalyDetector(config)
        self.model_registry = {}
        self.learning_enabled = True
        
    async def process_learning(self, command: Dict[str, Any], result: Dict[str, Any], metrics: Dict[str, float]):
        """Process command for learning"""
        if not self.learning_enabled:
            return
            
        # Detect anomalies
        is_anomaly, anomaly_score = self.anomaly_detector.detect_anomaly(command, metrics)
        
        if is_anomaly:
            logger.warning(
                "Anomaly detected",
                command_type=command.get("type"),
                anomaly_score=anomaly_score
            )
            
        # Learn from command sequence
        self.predictor.learn_from_sequence([command])
        
        # Update workflow optimization
        state = self._get_state_representation(command)
        action = command.get("action", "default")
        reward = self.optimizer.calculate_reward(
            metrics.get("execution_time", 0),
            result.get("success", False),
            metrics
        )
        next_state = self._get_state_representation(result)
        
        self.optimizer.update(state, action, reward, next_state)
        
    def _get_state_representation(self, data: Dict[str, Any]) -> str:
        """Get state representation for RL"""
        # Simplified state representation
        return f"{data.get('type', 'unknown')}_{data.get('status', 'unknown')}"
        
    async def get_predictions(self, context: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get all predictions and recommendations"""
        predictions = await self.predictor.predict_next(context)
        suggestions = self.optimizer.get_optimization_suggestions()
        anomaly_report = self.anomaly_detector.get_anomaly_report()
        
        return {
            "next_commands": predictions,
            "optimization_suggestions": suggestions,
            "anomaly_report": anomaly_report,
            "learning_stats": {
                "commands_processed": len(self.predictor.training_data),
                "workflows_optimized": len(self.optimizer.workflow_memory),
                "anomalies_detected": anomaly_report["anomalies_detected"]
            }
        }
        
    def save_models(self, path: str):
        """Save all trained models"""
        state = {
            "predictor_model": self.predictor.model.state_dict(),
            "predictor_encoder": self.predictor.encoder,
            "optimizer_q_table": dict(self.optimizer.q_table),
            "anomaly_detector": self.anomaly_detector.isolation_forest,
            "config": self.config
        }
        
        with open(path, "wb") as f:
            pickle.dump(state, f)
            
        logger.info(f"Models saved to {path}")
        
    def load_models(self, path: str):
        """Load trained models"""
        with open(path, "rb") as f:
            state = pickle.load(f)
            
        self.predictor.model.load_state_dict(state["predictor_model"])
        self.predictor.encoder = state["predictor_encoder"]
        self.optimizer.q_table = defaultdict(lambda: defaultdict(float), state["optimizer_q_table"])
        self.anomaly_detector.isolation_forest = state["anomaly_detector"]
        self.config = state["config"]
        
        logger.info(f"Models loaded from {path}")


class AdaptiveModel:
    """Adaptive model that adjusts based on performance"""
    
    def __init__(self, base_model: Any, adaptation_rate: float = 0.01):
        self.base_model = base_model
        self.adaptation_rate = adaptation_rate
        self.performance_window = deque(maxlen=100)
        self.adaptation_history = []
        
    def adapt(self, performance_metric: float):
        """Adapt model based on performance"""
        self.performance_window.append(performance_metric)
        
        if len(self.performance_window) < 10:
            return
            
        # Calculate performance trend
        recent_performance = np.mean(list(self.performance_window)[-10:])
        overall_performance = np.mean(list(self.performance_window))
        
        if recent_performance < overall_performance * 0.9:
            # Performance degrading - increase adaptation
            self._increase_adaptation()
        elif recent_performance > overall_performance * 1.1:
            # Performance improving - decrease adaptation
            self._decrease_adaptation()
            
    def _increase_adaptation(self):
        """Increase model adaptation rate"""
        self.adaptation_rate = min(0.1, self.adaptation_rate * 1.1)
        self.adaptation_history.append({
            "action": "increase",
            "new_rate": self.adaptation_rate,
            "timestamp": datetime.now()
        })
        
    def _decrease_adaptation(self):
        """Decrease model adaptation rate"""
        self.adaptation_rate = max(0.001, self.adaptation_rate * 0.9)
        self.adaptation_history.append({
            "action": "decrease", 
            "new_rate": self.adaptation_rate,
            "timestamp": datetime.now()
        })