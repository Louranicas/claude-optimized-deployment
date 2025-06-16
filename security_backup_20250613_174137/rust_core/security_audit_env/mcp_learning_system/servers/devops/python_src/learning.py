import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional, Any
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, mean_squared_error
import torch
import torch.nn as nn
import torch.optim as optim
from dataclasses import dataclass
import json
import logging

logger = logging.getLogger(__name__)

@dataclass
class DeploymentData:
    timestamp: datetime
    service: str
    environment: str
    version: str
    duration: float
    success: bool
    cpu_usage: float
    memory_usage: float
    error_rate: float
    response_time: float
    replicas: int
    dependencies: List[str]

@dataclass
class IncidentData:
    timestamp: datetime
    type: str
    severity: str
    affected_services: List[str]
    resolution_time: float
    root_cause: str
    remediation_actions: List[str]

@dataclass
class CapacityData:
    timestamp: datetime
    cpu_utilization: float
    memory_utilization: float
    storage_utilization: float
    network_utilization: float
    active_services: int
    request_rate: float

class DeploymentPredictor:
    def __init__(self):
        self.success_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.duration_regressor = GradientBoostingRegressor(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.feature_importance = {}
        self.is_trained = False
        
    def extract_features(self, deployment_data: List[DeploymentData]) -> np.ndarray:
        """Extract features from deployment data for ML models"""
        features = []
        
        for deployment in deployment_data:
            feature_vector = [
                deployment.timestamp.hour,
                deployment.timestamp.weekday(),
                deployment.cpu_usage,
                deployment.memory_usage,
                deployment.error_rate,
                deployment.response_time,
                deployment.replicas,
                len(deployment.dependencies),
                hash(deployment.environment) % 100,  # Environment encoding
                hash(deployment.service) % 1000,     # Service encoding
            ]
            features.append(feature_vector)
            
        return np.array(features)
    
    def train(self, deployment_data: List[DeploymentData]):
        """Train the prediction models"""
        if len(deployment_data) < 100:
            logger.warning("Insufficient data for training")
            return
            
        X = self.extract_features(deployment_data)
        y_success = np.array([d.success for d in deployment_data])
        y_duration = np.array([d.duration for d in deployment_data])
        
        # Normalize features
        X_scaled = self.scaler.fit_transform(X)
        
        # Split data
        X_train, X_test, y_success_train, y_success_test = train_test_split(
            X_scaled, y_success, test_size=0.2, random_state=42
        )
        _, _, y_duration_train, y_duration_test = train_test_split(
            X_scaled, y_duration, test_size=0.2, random_state=42
        )
        
        # Train success classifier
        self.success_classifier.fit(X_train, y_success_train)
        success_accuracy = accuracy_score(y_success_test, 
                                        self.success_classifier.predict(X_test))
        
        # Train duration regressor
        self.duration_regressor.fit(X_train, y_duration_train)
        duration_mse = mean_squared_error(y_duration_test, 
                                        self.duration_regressor.predict(X_test))
        
        # Store feature importance
        self.feature_importance = {
            'success': self.success_classifier.feature_importances_.tolist(),
            'duration': self.duration_regressor.feature_importances_.tolist()
        }
        
        self.is_trained = True
        logger.info(f"Models trained - Success accuracy: {success_accuracy:.2f}, "
                   f"Duration MSE: {duration_mse:.2f}")
    
    def predict(self, deployment: DeploymentData) -> Tuple[float, float]:
        """Predict success probability and duration"""
        if not self.is_trained:
            return 0.5, 300.0  # Default values
            
        features = self.extract_features([deployment])
        features_scaled = self.scaler.transform(features)
        
        success_prob = self.success_classifier.predict_proba(features_scaled)[0, 1]
        duration = self.duration_regressor.predict(features_scaled)[0]
        
        return float(success_prob), float(duration)
    
    def extract_factors(self, deployment_data: List[DeploymentData]) -> Dict[str, float]:
        """Extract success factors from deployment history"""
        if not deployment_data:
            return {}
            
        df = pd.DataFrame([
            {
                'hour': d.timestamp.hour,
                'weekday': d.timestamp.weekday(),
                'success': d.success,
                'duration': d.duration,
                'cpu': d.cpu_usage,
                'memory': d.memory_usage,
                'error_rate': d.error_rate,
            }
            for d in deployment_data
        ])
        
        # Analyze success factors
        factors = {}
        
        # Time-based factors
        hourly_success = df.groupby('hour')['success'].mean()
        factors['best_hour'] = int(hourly_success.idxmax())
        factors['worst_hour'] = int(hourly_success.idxmin())
        
        # Resource-based factors
        factors['optimal_cpu'] = float(df[df['success']]['cpu'].median())
        factors['optimal_memory'] = float(df[df['success']]['memory'].median())
        
        # Error correlation
        factors['error_threshold'] = float(df[~df['success']]['error_rate'].quantile(0.25))
        
        return factors

class IncidentClassifier:
    def __init__(self):
        self.classifier = RandomForestClassifier(n_estimators=50, random_state=42)
        self.vectorizer = {}  # Would use TF-IDF in production
        self.is_trained = False
        
    def extract_features(self, incident_data: List[IncidentData]) -> np.ndarray:
        """Extract features from incident data"""
        features = []
        
        for incident in incident_data:
            feature_vector = [
                hash(incident.type) % 100,
                {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}.get(incident.severity, 0),
                len(incident.affected_services),
                incident.resolution_time,
                len(incident.remediation_actions),
                incident.timestamp.hour,
                incident.timestamp.weekday(),
            ]
            features.append(feature_vector)
            
        return np.array(features)
    
    def train(self, incident_data: List[IncidentData]):
        """Train the incident classifier"""
        if len(incident_data) < 50:
            logger.warning("Insufficient incident data for training")
            return
            
        X = self.extract_features(incident_data)
        y = np.array([hash(i.root_cause) % 10 for i in incident_data])  # Simplified
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        self.classifier.fit(X_train, y_train)
        accuracy = accuracy_score(y_test, self.classifier.predict(X_test))
        
        self.is_trained = True
        logger.info(f"Incident classifier trained - Accuracy: {accuracy:.2f}")
    
    def assess_risk(self, deployment_data: List[DeploymentData]) -> Dict[str, float]:
        """Assess incident risk for deployments"""
        if not deployment_data:
            return {}
            
        risk_factors = {
            'high_error_rate_risk': 0.0,
            'resource_exhaustion_risk': 0.0,
            'dependency_failure_risk': 0.0,
            'timing_risk': 0.0,
        }
        
        # Analyze recent deployments
        recent_errors = [d.error_rate for d in deployment_data[-10:]]
        if recent_errors:
            risk_factors['high_error_rate_risk'] = min(1.0, np.mean(recent_errors) * 2)
        
        # Resource exhaustion risk
        recent_cpu = [d.cpu_usage for d in deployment_data[-10:]]
        recent_memory = [d.memory_usage for d in deployment_data[-10:]]
        if recent_cpu and recent_memory:
            risk_factors['resource_exhaustion_risk'] = max(
                np.percentile(recent_cpu, 95) / 100,
                np.percentile(recent_memory, 95) / 100
            )
        
        # Dependency risk
        dependency_counts = [len(d.dependencies) for d in deployment_data]
        if dependency_counts:
            risk_factors['dependency_failure_risk'] = min(1.0, np.mean(dependency_counts) / 10)
        
        # Timing risk (deployments during peak hours)
        peak_hour_deployments = [d for d in deployment_data 
                                if 9 <= d.timestamp.hour <= 17]
        risk_factors['timing_risk'] = len(peak_hour_deployments) / max(1, len(deployment_data))
        
        return risk_factors

class CapacityForecaster:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.lookback_window = 24  # hours
        
    def prepare_time_series(self, capacity_data: List[CapacityData]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare time series data for forecasting"""
        if len(capacity_data) < self.lookback_window:
            return np.array([]), np.array([])
            
        # Sort by timestamp
        sorted_data = sorted(capacity_data, key=lambda x: x.timestamp)
        
        # Extract features
        features = []
        targets = []
        
        for i in range(len(sorted_data) - self.lookback_window):
            window = sorted_data[i:i + self.lookback_window]
            target = sorted_data[i + self.lookback_window]
            
            # Window features
            window_features = []
            for point in window:
                window_features.extend([
                    point.cpu_utilization,
                    point.memory_utilization,
                    point.storage_utilization,
                    point.network_utilization,
                    point.active_services,
                    point.request_rate,
                ])
            
            features.append(window_features)
            targets.append([
                target.cpu_utilization,
                target.memory_utilization,
                target.storage_utilization,
                target.network_utilization,
            ])
            
        return np.array(features), np.array(targets)
    
    def train(self, capacity_data: List[CapacityData]):
        """Train the capacity forecasting model"""
        X, y = self.prepare_time_series(capacity_data)
        
        if len(X) < 100:
            logger.warning("Insufficient capacity data for training")
            return
            
        # Use a simple neural network for forecasting
        self.model = CapacityForecastNetwork(
            input_size=X.shape[1],
            hidden_size=128,
            output_size=y.shape[1]
        )
        
        # Normalize data
        X_scaled = self.scaler.fit_transform(X)
        
        # Convert to tensors
        X_tensor = torch.FloatTensor(X_scaled)
        y_tensor = torch.FloatTensor(y)
        
        # Train the model
        optimizer = optim.Adam(self.model.parameters(), lr=0.001)
        criterion = nn.MSELoss()
        
        for epoch in range(100):
            optimizer.zero_grad()
            outputs = self.model(X_tensor)
            loss = criterion(outputs, y_tensor)
            loss.backward()
            optimizer.step()
            
            if epoch % 20 == 0:
                logger.info(f"Capacity forecast training - Epoch {epoch}, Loss: {loss.item():.4f}")
    
    def optimize(self, deployment_data: List[DeploymentData]) -> Dict[str, Any]:
        """Optimize resource allocation based on deployment patterns"""
        if not deployment_data:
            return {}
            
        df = pd.DataFrame([
            {
                'timestamp': d.timestamp,
                'cpu': d.cpu_usage,
                'memory': d.memory_usage,
                'replicas': d.replicas,
                'success': d.success,
            }
            for d in deployment_data
        ])
        
        suggestions = {}
        
        # Analyze resource utilization patterns
        cpu_by_hour = df.groupby(df['timestamp'].dt.hour)['cpu'].mean()
        memory_by_hour = df.groupby(df['timestamp'].dt.hour)['memory'].mean()
        
        # Suggest scaling schedule
        suggestions['scaling_schedule'] = {
            'scale_up_hours': cpu_by_hour[cpu_by_hour > cpu_by_hour.mean() + cpu_by_hour.std()].index.tolist(),
            'scale_down_hours': cpu_by_hour[cpu_by_hour < cpu_by_hour.mean() - cpu_by_hour.std()].index.tolist(),
        }
        
        # Optimal resource allocation
        successful_deployments = df[df['success']]
        if not successful_deployments.empty:
            suggestions['optimal_resources'] = {
                'cpu': float(successful_deployments['cpu'].quantile(0.75)),
                'memory': float(successful_deployments['memory'].quantile(0.75)),
                'replicas': int(successful_deployments['replicas'].mode().iloc[0]),
            }
        
        # Cost optimization
        total_cpu_hours = df['cpu'].sum() * df['replicas'].sum() / 60
        potential_savings = total_cpu_hours * 0.1  # Assume 10% optimization possible
        suggestions['cost_optimization'] = {
            'current_cpu_hours': float(total_cpu_hours),
            'potential_savings_percent': 10.0,
            'estimated_monthly_savings': float(potential_savings * 0.05),  # $0.05 per CPU hour
        }
        
        return suggestions

class CostOptimizer:
    def __init__(self):
        self.pricing_model = {
            'cpu_hour': 0.05,
            'memory_gb_hour': 0.01,
            'storage_gb_month': 0.10,
            'network_gb': 0.12,
        }
        
    def analyze_costs(self, 
                     deployment_data: List[DeploymentData],
                     capacity_data: List[CapacityData]) -> Dict[str, Any]:
        """Analyze and optimize infrastructure costs"""
        
        # Calculate current costs
        total_cpu_cost = sum(d.cpu_usage * d.duration / 3600 * self.pricing_model['cpu_hour'] 
                            for d in deployment_data)
        total_memory_cost = sum(d.memory_usage * d.duration / 3600 * self.pricing_model['memory_gb_hour'] 
                               for d in deployment_data)
        
        # Identify optimization opportunities
        optimizations = []
        
        # Over-provisioned services
        for service in set(d.service for d in deployment_data):
            service_deployments = [d for d in deployment_data if d.service == service]
            if service_deployments:
                avg_cpu = np.mean([d.cpu_usage for d in service_deployments])
                max_cpu = np.max([d.cpu_usage for d in service_deployments])
                
                if max_cpu > avg_cpu * 2:
                    optimizations.append({
                        'type': 'right_size',
                        'service': service,
                        'current_allocation': max_cpu,
                        'recommended_allocation': avg_cpu * 1.5,
                        'estimated_savings': (max_cpu - avg_cpu * 1.5) * 720 * self.pricing_model['cpu_hour'],
                    })
        
        # Time-based optimization
        hourly_usage = {}
        for d in deployment_data:
            hour = d.timestamp.hour
            if hour not in hourly_usage:
                hourly_usage[hour] = []
            hourly_usage[hour].append(d.cpu_usage)
        
        low_usage_hours = [hour for hour, usage in hourly_usage.items() 
                          if np.mean(usage) < 0.3]
        
        if low_usage_hours:
            optimizations.append({
                'type': 'scheduled_scaling',
                'hours': low_usage_hours,
                'potential_savings': len(low_usage_hours) * 0.7 * self.pricing_model['cpu_hour'],
            })
        
        return {
            'current_monthly_cost': {
                'cpu': total_cpu_cost * 30,
                'memory': total_memory_cost * 30,
                'total': (total_cpu_cost + total_memory_cost) * 30,
            },
            'optimizations': optimizations,
            'total_potential_savings': sum(o.get('estimated_savings', 0) + o.get('potential_savings', 0) 
                                         for o in optimizations),
        }

class CapacityForecastNetwork(nn.Module):
    def __init__(self, input_size, hidden_size, output_size):
        super().__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, batch_first=True)
        self.fc = nn.Linear(hidden_size, output_size)
        
    def forward(self, x):
        if len(x.shape) == 2:
            x = x.unsqueeze(1)
        lstm_out, _ = self.lstm(x)
        output = self.fc(lstm_out[:, -1, :])
        return output

class DevOpsLearning:
    def __init__(self):
        self.deployment_predictor = DeploymentPredictor()
        self.incident_classifier = IncidentClassifier()
        self.capacity_forecaster = CapacityForecaster()
        self.cost_optimizer = CostOptimizer()
        
    async def learn_deployment_patterns(self, deployment_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Learn from deployment history and generate insights"""
        
        # Convert to typed data
        typed_data = [
            DeploymentData(**d) if isinstance(d, dict) else d 
            for d in deployment_data
        ]
        
        # Train models
        self.deployment_predictor.train(typed_data)
        
        # Extract patterns
        patterns = self._analyze_deployment_times(typed_data)
        success_factors = self.deployment_predictor.extract_factors(typed_data)
        incident_risk = self.incident_classifier.assess_risk(typed_data)
        resource_suggestions = self.capacity_forecaster.optimize(typed_data)
        
        return {
            'patterns': patterns,
            'success_factors': success_factors,
            'incident_risk': incident_risk,
            'resource_suggestions': resource_suggestions,
        }
    
    def _analyze_deployment_times(self, deployment_data: List[DeploymentData]) -> Dict[str, Any]:
        """Analyze deployment timing patterns"""
        if not deployment_data:
            return {}
            
        df = pd.DataFrame([
            {
                'hour': d.timestamp.hour,
                'weekday': d.timestamp.weekday(),
                'success': d.success,
                'duration': d.duration,
            }
            for d in deployment_data
        ])
        
        patterns = {
            'hourly_success_rate': df.groupby('hour')['success'].mean().to_dict(),
            'weekday_success_rate': df.groupby('weekday')['success'].mean().to_dict(),
            'average_duration_by_hour': df.groupby('hour')['duration'].mean().to_dict(),
            'optimal_deployment_windows': self._find_optimal_windows(df),
        }
        
        return patterns
    
    def _find_optimal_windows(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Find optimal deployment time windows"""
        windows = []
        
        # Group by hour and calculate metrics
        hourly_stats = df.groupby('hour').agg({
            'success': ['mean', 'count'],
            'duration': 'mean'
        })
        
        # Find hours with high success rate and sufficient data
        for hour in hourly_stats.index:
            success_rate = hourly_stats.loc[hour, ('success', 'mean')]
            count = hourly_stats.loc[hour, ('success', 'count')]
            avg_duration = hourly_stats.loc[hour, ('duration', 'mean')]
            
            if success_rate > 0.9 and count >= 5:
                windows.append({
                    'hour': int(hour),
                    'success_rate': float(success_rate),
                    'average_duration': float(avg_duration),
                    'sample_size': int(count),
                })
        
        return sorted(windows, key=lambda x: x['success_rate'], reverse=True)[:5]
    
    async def predict_deployment_outcome(self, 
                                       deployment: Dict[str, Any],
                                       historical_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Predict deployment outcome using trained models"""
        
        # Convert deployment to typed data
        typed_deployment = DeploymentData(**deployment) if isinstance(deployment, dict) else deployment
        typed_historical = [
            DeploymentData(**d) if isinstance(d, dict) else d 
            for d in historical_data
        ]
        
        # Ensure models are trained
        if not self.deployment_predictor.is_trained and typed_historical:
            self.deployment_predictor.train(typed_historical)
        
        # Get predictions
        success_prob, duration = self.deployment_predictor.predict(typed_deployment)
        
        # Get risk assessment
        risk_assessment = self.incident_classifier.assess_risk(typed_historical + [typed_deployment])
        
        return {
            'success_probability': success_prob,
            'estimated_duration': duration,
            'risk_factors': risk_assessment,
            'confidence': 0.85 if self.deployment_predictor.is_trained else 0.5,
            'recommendations': self._generate_recommendations(success_prob, risk_assessment),
        }
    
    def _generate_recommendations(self, 
                                success_prob: float, 
                                risk_factors: Dict[str, float]) -> List[str]:
        """Generate deployment recommendations"""
        recommendations = []
        
        if success_prob < 0.7:
            recommendations.append("Consider using canary deployment strategy")
            recommendations.append("Increase testing coverage before deployment")
        
        if risk_factors.get('resource_exhaustion_risk', 0) > 0.7:
            recommendations.append("Pre-scale resources before deployment")
            recommendations.append("Enable auto-scaling policies")
        
        if risk_factors.get('timing_risk', 0) > 0.5:
            recommendations.append("Consider deploying during off-peak hours")
        
        if risk_factors.get('dependency_failure_risk', 0) > 0.6:
            recommendations.append("Verify all dependencies are healthy")
            recommendations.append("Consider implementing circuit breakers")
        
        return recommendations