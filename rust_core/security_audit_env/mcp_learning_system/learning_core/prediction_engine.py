"""
Prediction Engine - Advanced predictive capabilities using ensemble methods
"""

import asyncio
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import numpy as np
import torch
import torch.nn as nn
from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
import xgboost as xgb
import lightgbm as lgb

from .models import Context, Prediction, Patterns, KnowledgeGraph


@dataclass
class PredictionRequest:
    """Request for prediction"""
    context: Context
    target_type: str  # action, outcome, metric, state
    time_horizon: Optional[timedelta] = None
    confidence_threshold: float = 0.7


@dataclass
class ModelPerformance:
    """Track model performance"""
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    last_updated: datetime
    prediction_count: int


class PredictionEngine:
    """Main prediction engine with ensemble methods"""
    
    def __init__(self):
        self.models = self._initialize_models()
        self.ensemble = PredictionEnsemble()
        self.temporal_predictor = TemporalPredictor()
        self.causal_predictor = CausalPredictor()
        self.probabilistic_predictor = ProbabilisticPredictor()
        self.performance_tracker = PerformanceTracker()
        
    def _initialize_models(self) -> Dict[str, Any]:
        """Initialize prediction models"""
        return {
            "neural": NeuralPredictor(),
            "tree_based": TreeBasedPredictor(),
            "sequence": SequencePredictor(),
            "graph": GraphPredictor(),
            "bayesian": BayesianPredictor()
        }
    
    async def predict(self, context: Context, patterns: Patterns, 
                     knowledge_graph: KnowledgeGraph) -> Prediction:
        """Generate prediction based on context, patterns, and knowledge"""
        # Prepare features
        features = await self._prepare_features(context, patterns, knowledge_graph)
        
        # Get predictions from all models
        predictions = await self._get_model_predictions(features)
        
        # Ensemble predictions
        ensemble_prediction = await self.ensemble.combine(predictions)
        
        # Add temporal aspects
        temporal_adjustment = await self.temporal_predictor.adjust(
            ensemble_prediction,
            context.timestamp
        )
        
        # Add causal reasoning
        causal_factors = await self.causal_predictor.analyze(
            ensemble_prediction,
            knowledge_graph
        )
        
        # Generate probabilistic predictions
        probability_distribution = await self.probabilistic_predictor.generate(
            ensemble_prediction,
            predictions
        )
        
        # Create final prediction
        final_prediction = Prediction(
            output=ensemble_prediction.output,
            confidence=ensemble_prediction.confidence,
            temporal_adjustment=temporal_adjustment,
            causal_factors=causal_factors,
            probability_distribution=probability_distribution,
            model_contributions=self._get_model_contributions(predictions),
            timestamp=datetime.utcnow()
        )
        
        # Track performance
        await self.performance_tracker.track(final_prediction)
        
        return final_prediction
    
    async def predict_sequence(self, context_sequence: List[Context], 
                             horizon: int = 5) -> List[Prediction]:
        """Predict a sequence of future states"""
        predictions = []
        current_context = context_sequence[-1]
        
        for i in range(horizon):
            # Predict next state
            prediction = await self.predict(
                current_context,
                Patterns(),  # Will be extracted from context
                KnowledgeGraph()  # Will be loaded from current state
            )
            
            predictions.append(prediction)
            
            # Update context for next prediction
            current_context = self._update_context(current_context, prediction)
        
        return predictions
    
    async def predict_with_uncertainty(self, request: PredictionRequest) -> Dict[str, Any]:
        """Make prediction with uncertainty quantification"""
        # Generate multiple predictions with dropout/noise
        predictions = []
        
        for i in range(10):  # Monte Carlo sampling
            # Add noise to context
            noisy_context = self._add_noise_to_context(request.context, i)
            
            # Get prediction
            pred = await self.predict(
                noisy_context,
                Patterns(),
                KnowledgeGraph()
            )
            
            predictions.append(pred)
        
        # Calculate uncertainty
        uncertainty = self._calculate_uncertainty(predictions)
        
        # Get mean prediction
        mean_prediction = self._aggregate_predictions(predictions)
        
        return {
            "prediction": mean_prediction,
            "uncertainty": uncertainty,
            "confidence_interval": self._calculate_confidence_interval(predictions),
            "prediction_samples": predictions
        }
    
    async def _prepare_features(self, context: Context, patterns: Patterns,
                              knowledge_graph: KnowledgeGraph) -> np.ndarray:
        """Prepare features for prediction"""
        features = []
        
        # Context features
        context_features = self._extract_context_features(context)
        features.extend(context_features)
        
        # Pattern features
        pattern_features = self._extract_pattern_features(patterns)
        features.extend(pattern_features)
        
        # Knowledge graph features
        graph_features = self._extract_graph_features(knowledge_graph, context)
        features.extend(graph_features)
        
        # Interaction features
        interaction_features = self._create_interaction_features(
            context_features,
            pattern_features,
            graph_features
        )
        features.extend(interaction_features)
        
        return np.array(features)
    
    async def _get_model_predictions(self, features: np.ndarray) -> Dict[str, Prediction]:
        """Get predictions from all models"""
        tasks = []
        
        for name, model in self.models.items():
            task = asyncio.create_task(
                self._get_single_prediction(name, model, features)
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        return {name: pred for name, pred in zip(self.models.keys(), results)}
    
    async def _get_single_prediction(self, name: str, model: Any, 
                                   features: np.ndarray) -> Prediction:
        """Get prediction from a single model"""
        return await asyncio.to_thread(model.predict, features)
    
    def _extract_context_features(self, context: Context) -> List[float]:
        """Extract features from context"""
        features = []
        
        # Temporal features
        if hasattr(context, 'timestamp'):
            features.extend([
                context.timestamp.hour / 24,
                context.timestamp.weekday() / 7,
                context.timestamp.day / 31,
                context.timestamp.month / 12
            ])
        
        # State features
        if hasattr(context, 'state'):
            state_encoding = self._encode_state(context.state)
            features.extend(state_encoding)
        
        # User features
        if hasattr(context, 'user_attributes'):
            user_features = self._encode_user_attributes(context.user_attributes)
            features.extend(user_features)
        
        # Environment features
        if hasattr(context, 'environment'):
            env_features = self._encode_environment(context.environment)
            features.extend(env_features)
        
        return features
    
    def _extract_pattern_features(self, patterns: Patterns) -> List[float]:
        """Extract features from patterns"""
        features = []
        
        # Temporal pattern features
        if hasattr(patterns, 'temporal'):
            features.append(len(patterns.temporal))
            if patterns.temporal:
                avg_confidence = np.mean([p.confidence for p in patterns.temporal])
                features.append(avg_confidence)
            else:
                features.append(0.0)
        
        # Structural pattern features
        if hasattr(patterns, 'structural'):
            features.append(len(patterns.structural))
            if patterns.structural:
                avg_centrality = np.mean([p.centrality for p in patterns.structural])
                features.append(avg_centrality)
            else:
                features.append(0.0)
        
        # Anomaly features
        if hasattr(patterns, 'anomalies'):
            features.append(len(patterns.anomalies))
            anomaly_severity = self._calculate_anomaly_severity(patterns.anomalies)
            features.append(anomaly_severity)
        
        # Cluster features
        if hasattr(patterns, 'clusters'):
            features.append(len(patterns.clusters))
            if patterns.clusters:
                avg_density = np.mean([c.density for c in patterns.clusters])
                features.append(avg_density)
            else:
                features.append(0.0)
        
        return features
    
    def _extract_graph_features(self, knowledge_graph: KnowledgeGraph, 
                              context: Context) -> List[float]:
        """Extract features from knowledge graph"""
        features = []
        
        # Graph statistics
        features.extend([
            knowledge_graph.node_count() / 1000,  # Normalized
            knowledge_graph.edge_count() / 10000,  # Normalized
            knowledge_graph.density(),
            knowledge_graph.average_degree()
        ])
        
        # Context-specific graph features
        if hasattr(context, 'entity_id'):
            # Get node-specific features
            node_features = knowledge_graph.get_node_features(context.entity_id)
            features.extend(node_features[:10])  # First 10 features
        
        return features
    
    def _create_interaction_features(self, context_features: List[float],
                                   pattern_features: List[float],
                                   graph_features: List[float]) -> List[float]:
        """Create interaction features between feature groups"""
        interaction_features = []
        
        # Pairwise products (limited to avoid explosion)
        for i in range(min(5, len(context_features))):
            for j in range(min(5, len(pattern_features))):
                interaction_features.append(context_features[i] * pattern_features[j])
        
        # Ratios
        if len(graph_features) > 0 and graph_features[0] > 0:
            for feat in pattern_features[:3]:
                interaction_features.append(feat / graph_features[0])
        
        return interaction_features
    
    def _get_model_contributions(self, predictions: Dict[str, Prediction]) -> Dict[str, float]:
        """Calculate contribution of each model to final prediction"""
        contributions = {}
        total_confidence = sum(p.confidence for p in predictions.values())
        
        if total_confidence > 0:
            for name, pred in predictions.items():
                contributions[name] = pred.confidence / total_confidence
        else:
            # Equal contribution if no confidence
            for name in predictions:
                contributions[name] = 1.0 / len(predictions)
        
        return contributions
    
    def _update_context(self, context: Context, prediction: Prediction) -> Context:
        """Update context based on prediction"""
        new_context = Context()
        
        # Copy existing context
        for attr in dir(context):
            if not attr.startswith('_'):
                setattr(new_context, attr, getattr(context, attr))
        
        # Update based on prediction
        if hasattr(prediction, 'output'):
            new_context.previous_prediction = prediction.output
        
        # Update timestamp
        new_context.timestamp = datetime.utcnow()
        
        return new_context
    
    def _add_noise_to_context(self, context: Context, seed: int) -> Context:
        """Add noise to context for uncertainty estimation"""
        np.random.seed(seed)
        noisy_context = Context()
        
        # Copy context with noise
        for attr in dir(context):
            if not attr.startswith('_'):
                value = getattr(context, attr)
                
                # Add noise to numeric values
                if isinstance(value, (int, float)):
                    noise = np.random.normal(0, 0.1)
                    setattr(noisy_context, attr, value + noise * abs(value))
                else:
                    setattr(noisy_context, attr, value)
        
        return noisy_context
    
    def _calculate_uncertainty(self, predictions: List[Prediction]) -> Dict[str, float]:
        """Calculate uncertainty metrics from multiple predictions"""
        # Extract outputs
        outputs = []
        for pred in predictions:
            if hasattr(pred, 'output') and isinstance(pred.output, dict):
                outputs.append(list(pred.output.values()))
        
        if not outputs:
            return {"epistemic": 0.0, "aleatoric": 0.0, "total": 0.0}
        
        outputs = np.array(outputs)
        
        # Epistemic uncertainty (model uncertainty)
        epistemic = np.mean(np.std(outputs, axis=0))
        
        # Aleatoric uncertainty (data uncertainty)
        aleatoric = np.mean([pred.confidence for pred in predictions])
        
        return {
            "epistemic": float(epistemic),
            "aleatoric": float(1 - aleatoric),
            "total": float(epistemic + (1 - aleatoric))
        }
    
    def _aggregate_predictions(self, predictions: List[Prediction]) -> Prediction:
        """Aggregate multiple predictions into one"""
        if not predictions:
            return Prediction()
        
        # Aggregate outputs
        aggregated_output = {}
        
        for pred in predictions:
            if hasattr(pred, 'output') and isinstance(pred.output, dict):
                for key, value in pred.output.items():
                    if key not in aggregated_output:
                        aggregated_output[key] = []
                    aggregated_output[key].append(value)
        
        # Calculate means
        mean_output = {}
        for key, values in aggregated_output.items():
            mean_output[key] = np.mean(values)
        
        # Calculate mean confidence
        mean_confidence = np.mean([p.confidence for p in predictions])
        
        return Prediction(
            output=mean_output,
            confidence=mean_confidence,
            model="ensemble_aggregate",
            timestamp=datetime.utcnow()
        )
    
    def _calculate_confidence_interval(self, predictions: List[Prediction], 
                                     confidence_level: float = 0.95) -> Dict[str, Tuple[float, float]]:
        """Calculate confidence intervals for predictions"""
        intervals = {}
        
        # Extract outputs
        outputs = {}
        for pred in predictions:
            if hasattr(pred, 'output') and isinstance(pred.output, dict):
                for key, value in pred.output.items():
                    if key not in outputs:
                        outputs[key] = []
                    outputs[key].append(value)
        
        # Calculate intervals
        for key, values in outputs.items():
            if values:
                sorted_values = sorted(values)
                n = len(sorted_values)
                
                # Calculate percentiles
                lower_idx = int((1 - confidence_level) / 2 * n)
                upper_idx = int((1 + confidence_level) / 2 * n)
                
                intervals[key] = (
                    sorted_values[lower_idx],
                    sorted_values[min(upper_idx, n-1)]
                )
        
        return intervals
    
    def _encode_state(self, state: Dict[str, Any]) -> List[float]:
        """Encode state dictionary to features"""
        features = []
        
        for key, value in state.items():
            if isinstance(value, (int, float)):
                features.append(float(value))
            elif isinstance(value, bool):
                features.append(1.0 if value else 0.0)
            elif isinstance(value, str):
                # Simple hash encoding
                features.append(hash(value) % 1000 / 1000)
        
        # Pad or truncate to fixed size
        target_size = 20
        if len(features) < target_size:
            features.extend([0.0] * (target_size - len(features)))
        else:
            features = features[:target_size]
        
        return features
    
    def _encode_user_attributes(self, attributes: Dict[str, Any]) -> List[float]:
        """Encode user attributes"""
        return self._encode_state(attributes)[:10]  # Limit to 10 features
    
    def _encode_environment(self, environment: Dict[str, Any]) -> List[float]:
        """Encode environment information"""
        return self._encode_state(environment)[:10]  # Limit to 10 features
    
    def _calculate_anomaly_severity(self, anomalies: List[Any]) -> float:
        """Calculate overall anomaly severity"""
        if not anomalies:
            return 0.0
        
        severities = []
        severity_map = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
        
        for anomaly in anomalies:
            if hasattr(anomaly, 'severity'):
                severities.append(severity_map.get(anomaly.severity, 0.5))
        
        return np.mean(severities) if severities else 0.0


class NeuralPredictor:
    """Neural network based predictor"""
    
    def __init__(self):
        self.model = self._build_model()
        self.scaler = None
        
    def _build_model(self) -> nn.Module:
        """Build neural network model"""
        class PredictionNet(nn.Module):
            def __init__(self, input_size=100, hidden_sizes=[256, 128, 64], output_size=10):
                super().__init__()
                
                layers = []
                prev_size = input_size
                
                for hidden_size in hidden_sizes:
                    layers.extend([
                        nn.Linear(prev_size, hidden_size),
                        nn.ReLU(),
                        nn.Dropout(0.2),
                        nn.BatchNorm1d(hidden_size)
                    ])
                    prev_size = hidden_size
                
                layers.append(nn.Linear(prev_size, output_size))
                
                self.network = nn.Sequential(*layers)
                
            def forward(self, x):
                return self.network(x)
        
        return PredictionNet()
    
    def predict(self, features: np.ndarray) -> Prediction:
        """Make prediction using neural network"""
        # Convert to tensor
        if len(features.shape) == 1:
            features = features.reshape(1, -1)
        
        # Pad features if necessary
        if features.shape[1] < 100:
            padding = np.zeros((features.shape[0], 100 - features.shape[1]))
            features = np.hstack([features, padding])
        
        x = torch.FloatTensor(features)
        
        # Make prediction
        self.model.eval()
        with torch.no_grad():
            output = self.model(x)
            
        # Convert to prediction
        output_dict = {
            f"output_{i}": float(output[0, i])
            for i in range(output.shape[1])
        }
        
        # Calculate confidence based on output variance
        confidence = 1.0 / (1.0 + torch.std(output).item())
        
        return Prediction(
            output=output_dict,
            confidence=confidence,
            model="neural",
            timestamp=datetime.utcnow()
        )


class TreeBasedPredictor:
    """Tree-based ensemble predictor"""
    
    def __init__(self):
        self.models = {
            "rf": RandomForestRegressor(n_estimators=100, random_state=42),
            "gb": GradientBoostingRegressor(n_estimators=100, random_state=42),
            "xgb": xgb.XGBRegressor(n_estimators=100, random_state=42),
            "lgb": lgb.LGBMRegressor(n_estimators=100, random_state=42)
        }
        self._is_trained = False
        
    def predict(self, features: np.ndarray) -> Prediction:
        """Make prediction using tree-based models"""
        if not self._is_trained:
            # Use dummy training for now
            self._dummy_train(features)
        
        predictions = {}
        confidences = []
        
        # Get predictions from each model
        for name, model in self.models.items():
            try:
                pred = model.predict(features.reshape(1, -1))
                predictions[name] = float(pred[0])
                
                # Estimate confidence (placeholder)
                confidences.append(0.8)
            except:
                predictions[name] = 0.0
                confidences.append(0.0)
        
        # Combine predictions
        combined_output = {
            "mean": np.mean(list(predictions.values())),
            "std": np.std(list(predictions.values())),
            **predictions
        }
        
        return Prediction(
            output=combined_output,
            confidence=np.mean(confidences),
            model="tree_ensemble",
            timestamp=datetime.utcnow()
        )
    
    def _dummy_train(self, features: np.ndarray):
        """Dummy training for initialization"""
        # Create dummy data
        n_samples = 100
        X = np.random.randn(n_samples, features.shape[0])
        y = np.random.randn(n_samples)
        
        # Train models
        for model in self.models.values():
            try:
                model.fit(X, y)
            except:
                pass
        
        self._is_trained = True


class SequencePredictor:
    """Sequence-based predictor for time series"""
    
    def __init__(self):
        self.lstm_model = self._build_lstm()
        self.transformer_model = self._build_transformer()
        
    def _build_lstm(self) -> nn.Module:
        """Build LSTM model"""
        class LSTMPredictor(nn.Module):
            def __init__(self, input_size=100, hidden_size=128, num_layers=2, output_size=10):
                super().__init__()
                self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True)
                self.fc = nn.Linear(hidden_size, output_size)
                
            def forward(self, x):
                # x shape: (batch, seq_len, features)
                lstm_out, _ = self.lstm(x)
                # Use last output
                return self.fc(lstm_out[:, -1, :])
        
        return LSTMPredictor()
    
    def _build_transformer(self) -> nn.Module:
        """Build transformer model"""
        class TransformerPredictor(nn.Module):
            def __init__(self, input_size=100, d_model=128, nhead=8, num_layers=2, output_size=10):
                super().__init__()
                self.input_projection = nn.Linear(input_size, d_model)
                self.transformer = nn.TransformerEncoder(
                    nn.TransformerEncoderLayer(d_model, nhead, batch_first=True),
                    num_layers
                )
                self.output_projection = nn.Linear(d_model, output_size)
                
            def forward(self, x):
                # Project input
                x = self.input_projection(x)
                # Apply transformer
                x = self.transformer(x)
                # Use mean pooling
                x = x.mean(dim=1)
                return self.output_projection(x)
        
        return TransformerPredictor()
    
    def predict(self, features: np.ndarray) -> Prediction:
        """Make sequence prediction"""
        # Reshape for sequence model (add sequence dimension)
        if len(features.shape) == 1:
            features = features.reshape(1, 1, -1)
        elif len(features.shape) == 2:
            features = features.reshape(features.shape[0], 1, -1)
        
        # Pad if necessary
        if features.shape[2] < 100:
            padding = np.zeros((features.shape[0], features.shape[1], 100 - features.shape[2]))
            features = np.concatenate([features, padding], axis=2)
        
        x = torch.FloatTensor(features)
        
        # Get predictions from both models
        self.lstm_model.eval()
        self.transformer_model.eval()
        
        with torch.no_grad():
            lstm_output = self.lstm_model(x)
            transformer_output = self.transformer_model(x)
        
        # Combine outputs
        combined_output = {
            "lstm": {f"dim_{i}": float(lstm_output[0, i]) for i in range(lstm_output.shape[1])},
            "transformer": {f"dim_{i}": float(transformer_output[0, i]) for i in range(transformer_output.shape[1])},
            "mean": {f"dim_{i}": float((lstm_output[0, i] + transformer_output[0, i]) / 2) 
                    for i in range(min(lstm_output.shape[1], transformer_output.shape[1]))}
        }
        
        # Calculate confidence
        output_variance = torch.var(torch.stack([lstm_output, transformer_output])).item()
        confidence = 1.0 / (1.0 + output_variance)
        
        return Prediction(
            output=combined_output,
            confidence=confidence,
            model="sequence",
            timestamp=datetime.utcnow()
        )


class GraphPredictor:
    """Graph-based predictor using GNN"""
    
    def __init__(self):
        self.gnn_model = self._build_gnn()
        
    def _build_gnn(self) -> nn.Module:
        """Build Graph Neural Network"""
        # Simplified GNN for demonstration
        class SimpleGNN(nn.Module):
            def __init__(self, input_size=100, hidden_size=128, output_size=10):
                super().__init__()
                self.fc1 = nn.Linear(input_size, hidden_size)
                self.fc2 = nn.Linear(hidden_size, hidden_size)
                self.fc3 = nn.Linear(hidden_size, output_size)
                self.activation = nn.ReLU()
                
            def forward(self, x):
                x = self.activation(self.fc1(x))
                x = self.activation(self.fc2(x))
                return self.fc3(x)
        
        return SimpleGNN()
    
    def predict(self, features: np.ndarray) -> Prediction:
        """Make graph-based prediction"""
        # Ensure 2D
        if len(features.shape) == 1:
            features = features.reshape(1, -1)
        
        # Pad if necessary
        if features.shape[1] < 100:
            padding = np.zeros((features.shape[0], 100 - features.shape[1]))
            features = np.hstack([features, padding])
        
        x = torch.FloatTensor(features)
        
        # Make prediction
        self.gnn_model.eval()
        with torch.no_grad():
            output = self.gnn_model(x)
        
        output_dict = {
            f"graph_output_{i}": float(output[0, i])
            for i in range(output.shape[1])
        }
        
        return Prediction(
            output=output_dict,
            confidence=0.75,  # Fixed confidence for now
            model="graph",
            timestamp=datetime.utcnow()
        )


class BayesianPredictor:
    """Bayesian predictor with uncertainty quantification"""
    
    def __init__(self):
        self.prior_mean = 0.0
        self.prior_variance = 1.0
        self.observations = []
        
    def predict(self, features: np.ndarray) -> Prediction:
        """Make Bayesian prediction"""
        # Simple Bayesian prediction
        feature_mean = np.mean(features)
        
        # Update posterior
        if self.observations:
            obs_mean = np.mean(self.observations)
            obs_var = np.var(self.observations)
            
            # Bayesian update
            posterior_variance = 1 / (1/self.prior_variance + len(self.observations)/obs_var)
            posterior_mean = posterior_variance * (
                self.prior_mean/self.prior_variance + 
                len(self.observations)*obs_mean/obs_var
            )
        else:
            posterior_mean = self.prior_mean
            posterior_variance = self.prior_variance
        
        # Make prediction
        prediction_mean = posterior_mean + 0.1 * feature_mean
        prediction_variance = posterior_variance + 0.01
        
        output = {
            "mean": float(prediction_mean),
            "variance": float(prediction_variance),
            "lower_bound": float(prediction_mean - 2 * np.sqrt(prediction_variance)),
            "upper_bound": float(prediction_mean + 2 * np.sqrt(prediction_variance))
        }
        
        # Confidence based on variance
        confidence = 1.0 / (1.0 + prediction_variance)
        
        return Prediction(
            output=output,
            confidence=confidence,
            model="bayesian",
            timestamp=datetime.utcnow()
        )


class PredictionEnsemble:
    """Ensemble combiner for predictions"""
    
    def __init__(self):
        self.combination_methods = {
            "weighted_average": self._weighted_average,
            "stacking": self._stacking,
            "voting": self._voting,
            "bayesian_combination": self._bayesian_combination
        }
        self.meta_model = self._build_meta_model()
        
    def _build_meta_model(self) -> nn.Module:
        """Build meta-model for stacking"""
        class MetaModel(nn.Module):
            def __init__(self, n_models=5, n_features=10, output_size=10):
                super().__init__()
                input_size = n_models * n_features
                self.fc1 = nn.Linear(input_size, 128)
                self.fc2 = nn.Linear(128, 64)
                self.fc3 = nn.Linear(64, output_size)
                self.activation = nn.ReLU()
                self.dropout = nn.Dropout(0.2)
                
            def forward(self, x):
                x = self.activation(self.fc1(x))
                x = self.dropout(x)
                x = self.activation(self.fc2(x))
                x = self.dropout(x)
                return self.fc3(x)
        
        return MetaModel()
    
    async def combine(self, predictions: Dict[str, Prediction]) -> Prediction:
        """Combine multiple predictions"""
        if not predictions:
            return Prediction()
        
        # Try different combination methods
        results = {}
        
        for method_name, method in self.combination_methods.items():
            try:
                results[method_name] = await method(predictions)
            except:
                continue
        
        # Select best combination (based on confidence)
        best_method = max(results.items(), key=lambda x: x[1].confidence)
        
        return best_method[1]
    
    async def _weighted_average(self, predictions: Dict[str, Prediction]) -> Prediction:
        """Weighted average combination"""
        weights = {}
        outputs = {}
        
        # Calculate weights based on confidence
        total_confidence = sum(p.confidence for p in predictions.values())
        
        for name, pred in predictions.items():
            weights[name] = pred.confidence / total_confidence if total_confidence > 0 else 1/len(predictions)
            
            # Collect outputs
            if hasattr(pred, 'output') and isinstance(pred.output, dict):
                for key, value in pred.output.items():
                    if key not in outputs:
                        outputs[key] = []
                    outputs[key].append((value, weights[name]))
        
        # Calculate weighted averages
        combined_output = {}
        for key, values_weights in outputs.items():
            if values_weights:
                weighted_sum = sum(v * w for v, w in values_weights)
                total_weight = sum(w for _, w in values_weights)
                combined_output[key] = weighted_sum / total_weight if total_weight > 0 else 0
        
        return Prediction(
            output=combined_output,
            confidence=total_confidence / len(predictions) if predictions else 0,
            model="weighted_ensemble",
            timestamp=datetime.utcnow()
        )
    
    async def _stacking(self, predictions: Dict[str, Prediction]) -> Prediction:
        """Stacking combination using meta-model"""
        # Extract features from predictions
        features = []
        
        for name, pred in predictions.items():
            if hasattr(pred, 'output') and isinstance(pred.output, dict):
                # Take first 10 values or pad
                values = list(pred.output.values())[:10]
                if len(values) < 10:
                    values.extend([0.0] * (10 - len(values)))
                features.extend(values)
        
        # Ensure correct size
        expected_size = 50  # 5 models * 10 features
        if len(features) < expected_size:
            features.extend([0.0] * (expected_size - len(features)))
        elif len(features) > expected_size:
            features = features[:expected_size]
        
        # Use meta-model
        x = torch.FloatTensor(features).unsqueeze(0)
        
        self.meta_model.eval()
        with torch.no_grad():
            output = self.meta_model(x)
        
        output_dict = {
            f"stacked_output_{i}": float(output[0, i])
            for i in range(output.shape[1])
        }
        
        # Calculate confidence
        avg_confidence = np.mean([p.confidence for p in predictions.values()])
        
        return Prediction(
            output=output_dict,
            confidence=avg_confidence * 0.9,  # Slight penalty for complexity
            model="stacking_ensemble",
            timestamp=datetime.utcnow()
        )
    
    async def _voting(self, predictions: Dict[str, Prediction]) -> Prediction:
        """Voting combination"""
        # Collect all outputs
        all_outputs = {}
        
        for name, pred in predictions.items():
            if hasattr(pred, 'output') and isinstance(pred.output, dict):
                for key, value in pred.output.items():
                    if key not in all_outputs:
                        all_outputs[key] = []
                    all_outputs[key].append(value)
        
        # Use median for voting
        voted_output = {}
        for key, values in all_outputs.items():
            if values:
                voted_output[key] = float(np.median(values))
        
        # Confidence based on agreement
        confidence_scores = []
        for key, values in all_outputs.items():
            if len(values) > 1:
                # Calculate coefficient of variation
                cv = np.std(values) / (np.mean(values) + 1e-6)
                agreement = 1.0 / (1.0 + cv)
                confidence_scores.append(agreement)
        
        avg_confidence = np.mean(confidence_scores) if confidence_scores else 0.5
        
        return Prediction(
            output=voted_output,
            confidence=avg_confidence,
            model="voting_ensemble",
            timestamp=datetime.utcnow()
        )
    
    async def _bayesian_combination(self, predictions: Dict[str, Prediction]) -> Prediction:
        """Bayesian combination of predictions"""
        # Extract means and variances
        means = {}
        variances = {}
        
        for name, pred in predictions.items():
            if hasattr(pred, 'output') and isinstance(pred.output, dict):
                # Look for mean/variance or estimate
                if 'mean' in pred.output and 'variance' in pred.output:
                    means[name] = pred.output['mean']
                    variances[name] = pred.output['variance']
                else:
                    # Estimate from output values
                    values = list(pred.output.values())
                    if values:
                        means[name] = np.mean(values)
                        variances[name] = np.var(values) + 0.1  # Add small constant
        
        if not means:
            return Prediction()
        
        # Bayesian combination
        # Precision-weighted average
        precisions = {k: 1/v for k, v in variances.items()}
        total_precision = sum(precisions.values())
        
        combined_mean = sum(means[k] * precisions[k] for k in means) / total_precision
        combined_variance = 1 / total_precision
        
        output = {
            "mean": float(combined_mean),
            "variance": float(combined_variance),
            "std": float(np.sqrt(combined_variance)),
            "lower_95": float(combined_mean - 1.96 * np.sqrt(combined_variance)),
            "upper_95": float(combined_mean + 1.96 * np.sqrt(combined_variance))
        }
        
        # Confidence based on combined variance
        confidence = 1.0 / (1.0 + combined_variance)
        
        return Prediction(
            output=output,
            confidence=confidence,
            model="bayesian_ensemble",
            timestamp=datetime.utcnow()
        )


class TemporalPredictor:
    """Adjust predictions based on temporal factors"""
    
    async def adjust(self, prediction: Prediction, timestamp: datetime) -> Dict[str, Any]:
        """Adjust prediction for temporal factors"""
        adjustments = {}
        
        # Time of day adjustment
        hour = timestamp.hour
        if 0 <= hour < 6:
            adjustments["time_of_day_factor"] = 0.8  # Early morning
        elif 6 <= hour < 12:
            adjustments["time_of_day_factor"] = 1.1  # Morning
        elif 12 <= hour < 18:
            adjustments["time_of_day_factor"] = 1.0  # Afternoon
        else:
            adjustments["time_of_day_factor"] = 0.9  # Evening
        
        # Day of week adjustment
        weekday = timestamp.weekday()
        if weekday < 5:
            adjustments["day_of_week_factor"] = 1.0  # Weekday
        else:
            adjustments["day_of_week_factor"] = 0.85  # Weekend
        
        # Seasonal adjustment (simplified)
        month = timestamp.month
        if month in [12, 1, 2]:
            adjustments["seasonal_factor"] = 0.9  # Winter
        elif month in [3, 4, 5]:
            adjustments["seasonal_factor"] = 1.05  # Spring
        elif month in [6, 7, 8]:
            adjustments["seasonal_factor"] = 1.1  # Summer
        else:
            adjustments["seasonal_factor"] = 0.95  # Fall
        
        # Apply adjustments to prediction
        if hasattr(prediction, 'output') and isinstance(prediction.output, dict):
            adjusted_output = {}
            overall_factor = np.prod(list(adjustments.values()))
            
            for key, value in prediction.output.items():
                if isinstance(value, (int, float)):
                    adjusted_output[key] = value * overall_factor
                else:
                    adjusted_output[key] = value
            
            adjustments["adjusted_output"] = adjusted_output
        
        return adjustments


class CausalPredictor:
    """Analyze causal factors in predictions"""
    
    async def analyze(self, prediction: Prediction, 
                     knowledge_graph: KnowledgeGraph) -> Dict[str, Any]:
        """Analyze causal factors"""
        causal_factors = {
            "direct_causes": [],
            "indirect_causes": [],
            "confounders": [],
            "mediators": [],
            "causal_strength": {}
        }
        
        # Extract entities from prediction
        entities = self._extract_entities_from_prediction(prediction)
        
        # Find causal relationships in knowledge graph
        for entity in entities:
            # Direct causes
            direct = knowledge_graph.get_direct_causes(entity)
            causal_factors["direct_causes"].extend(direct)
            
            # Indirect causes
            indirect = knowledge_graph.get_indirect_causes(entity, max_depth=2)
            causal_factors["indirect_causes"].extend(indirect)
            
            # Confounders
            confounders = knowledge_graph.get_confounders(entity)
            causal_factors["confounders"].extend(confounders)
        
        # Calculate causal strength
        for cause in causal_factors["direct_causes"]:
            strength = knowledge_graph.get_causal_strength(cause["source"], cause["target"])
            causal_factors["causal_strength"][f"{cause['source']}->{cause['target']}"] = strength
        
        # Find mediators
        causal_factors["mediators"] = self._find_mediators(
            causal_factors["direct_causes"],
            causal_factors["indirect_causes"]
        )
        
        return causal_factors
    
    def _extract_entities_from_prediction(self, prediction: Prediction) -> List[str]:
        """Extract entity IDs from prediction"""
        entities = []
        
        if hasattr(prediction, 'output') and isinstance(prediction.output, dict):
            for key in prediction.output.keys():
                if "entity" in key or "id" in key:
                    entities.append(key)
        
        return entities
    
    def _find_mediators(self, direct_causes: List[Dict], 
                       indirect_causes: List[Dict]) -> List[Dict]:
        """Find mediating variables"""
        mediators = []
        
        # Simple mediation detection
        for indirect in indirect_causes:
            for direct in direct_causes:
                if (indirect["source"] == direct["source"] and 
                    indirect["target"] != direct["target"]):
                    mediators.append({
                        "mediator": direct["target"],
                        "source": indirect["source"],
                        "target": indirect["target"]
                    })
        
        return mediators


class ProbabilisticPredictor:
    """Generate probability distributions for predictions"""
    
    async def generate(self, prediction: Prediction, 
                      all_predictions: Dict[str, Prediction]) -> Dict[str, Any]:
        """Generate probability distribution"""
        distribution = {
            "type": "mixture",
            "components": [],
            "parameters": {},
            "quantiles": {},
            "moments": {}
        }
        
        # Collect all output values
        all_values = []
        for pred in all_predictions.values():
            if hasattr(pred, 'output') and isinstance(pred.output, dict):
                values = [v for v in pred.output.values() if isinstance(v, (int, float))]
                all_values.extend(values)
        
        if not all_values:
            return distribution
        
        # Fit mixture model
        from sklearn.mixture import GaussianMixture
        
        values_array = np.array(all_values).reshape(-1, 1)
        
        # Determine optimal number of components
        n_components = min(3, len(np.unique(all_values)))
        
        if n_components > 1:
            gmm = GaussianMixture(n_components=n_components, random_state=42)
            gmm.fit(values_array)
            
            # Extract components
            for i in range(n_components):
                distribution["components"].append({
                    "weight": float(gmm.weights_[i]),
                    "mean": float(gmm.means_[i, 0]),
                    "variance": float(gmm.covariances_[i, 0, 0])
                })
        
        # Calculate distribution parameters
        distribution["parameters"] = {
            "mean": float(np.mean(all_values)),
            "std": float(np.std(all_values)),
            "min": float(np.min(all_values)),
            "max": float(np.max(all_values))
        }
        
        # Calculate quantiles
        quantiles = [0.05, 0.25, 0.5, 0.75, 0.95]
        for q in quantiles:
            distribution["quantiles"][f"q{int(q*100)}"] = float(np.quantile(all_values, q))
        
        # Calculate moments
        distribution["moments"] = {
            "mean": float(np.mean(all_values)),
            "variance": float(np.var(all_values)),
            "skewness": float(self._calculate_skewness(all_values)),
            "kurtosis": float(self._calculate_kurtosis(all_values))
        }
        
        return distribution
    
    def _calculate_skewness(self, values: np.ndarray) -> float:
        """Calculate skewness"""
        if len(values) < 3:
            return 0.0
        
        mean = np.mean(values)
        std = np.std(values)
        
        if std == 0:
            return 0.0
        
        return np.mean(((values - mean) / std) ** 3)
    
    def _calculate_kurtosis(self, values: np.ndarray) -> float:
        """Calculate kurtosis"""
        if len(values) < 4:
            return 0.0
        
        mean = np.mean(values)
        std = np.std(values)
        
        if std == 0:
            return 0.0
        
        return np.mean(((values - mean) / std) ** 4) - 3


class PerformanceTracker:
    """Track prediction performance"""
    
    def __init__(self):
        self.predictions = []
        self.performance_metrics = {}
        
    async def track(self, prediction: Prediction):
        """Track a prediction"""
        self.predictions.append({
            "prediction": prediction,
            "timestamp": datetime.utcnow()
        })
        
        # Keep only recent predictions
        if len(self.predictions) > 1000:
            self.predictions = self.predictions[-1000:]
        
        # Update performance metrics
        await self._update_metrics()
    
    async def _update_metrics(self):
        """Update performance metrics"""
        if not self.predictions:
            return
        
        # Calculate metrics
        recent_predictions = self.predictions[-100:]
        
        confidences = [p["prediction"].confidence for p in recent_predictions]
        
        self.performance_metrics = {
            "avg_confidence": np.mean(confidences),
            "confidence_std": np.std(confidences),
            "prediction_rate": len(recent_predictions) / 100,
            "last_updated": datetime.utcnow()
        }
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary"""
        return self.performance_metrics.copy()