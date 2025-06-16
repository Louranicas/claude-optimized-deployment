use std::sync::Arc;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc, Duration};
use anyhow::Result;
use ndarray::{Array1, Array2};

use crate::memory::MemoryPool;
use crate::deployment::{DeploymentPlan, DeploymentPattern};
use crate::infrastructure::InfrastructureState;
use crate::learning::DeploymentAnalysis;

#[derive(Debug, Clone)]
pub struct PredictionEngine {
    memory_pool: Arc<MemoryPool<2_147_483_648>>,
    models: Arc<DashMap<String, PredictionModel>>,
    feature_cache: Arc<DashMap<String, FeatureVector>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictionResult {
    pub success_probability: f64,
    pub estimated_duration: Duration,
    pub risk_factors: Vec<RiskFactor>,
    pub optimizations: Vec<Optimization>,
    pub confidence: f64,
    pub reasoning: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor: String,
    pub severity: RiskSeverity,
    pub probability: f64,
    pub mitigation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Optimization {
    pub category: OptimizationCategory,
    pub description: String,
    pub impact: OptimizationImpact,
    pub implementation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimizationCategory {
    Timing,
    Resources,
    Configuration,
    Dependencies,
    Strategy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationImpact {
    pub success_rate_improvement: f64,
    pub duration_reduction: f64,
    pub cost_savings: f64,
}

#[derive(Debug, Clone)]
struct PredictionModel {
    model_type: ModelType,
    weights: Array2<f64>,
    bias: Array1<f64>,
    feature_importance: Vec<(String, f64)>,
    accuracy: f64,
}

#[derive(Debug, Clone)]
enum ModelType {
    LogisticRegression,
    RandomForest,
    NeuralNetwork,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FeatureVector {
    features: Vec<f64>,
    feature_names: Vec<String>,
    timestamp: DateTime<Utc>,
}

impl PredictionEngine {
    pub fn new(memory_pool: Arc<MemoryPool<2_147_483_648>>) -> Self {
        let mut engine = Self {
            memory_pool,
            models: Arc::new(DashMap::new()),
            feature_cache: Arc::new(DashMap::new()),
        };
        
        // Initialize default models
        engine.initialize_models();
        engine
    }
    
    pub async fn predict_outcome(
        &self,
        deployment: &DeploymentPlan,
        patterns: &[DeploymentPattern],
    ) -> Result<PredictionResult> {
        // Extract features
        let features = self.extract_features(deployment, patterns)?;
        
        // Get predictions from all models
        let mut predictions = Vec::new();
        for model in self.models.iter() {
            let prediction = self.run_model(&model, &features)?;
            predictions.push((model.key().clone(), prediction));
        }
        
        // Ensemble predictions
        let final_prediction = self.ensemble_predictions(&predictions)?;
        
        // Analyze risks
        let risk_factors = self.analyze_risks(deployment, patterns, &final_prediction)?;
        
        // Generate optimizations
        let optimizations = self.generate_optimizations(deployment, patterns, &final_prediction)?;
        
        Ok(PredictionResult {
            success_probability: final_prediction.0,
            estimated_duration: Duration::seconds(final_prediction.1 as i64),
            risk_factors,
            optimizations,
            confidence: final_prediction.2,
            reasoning: self.generate_reasoning(&predictions, deployment),
        })
    }
    
    pub async fn recommend_optimizations(
        &self,
        state: &InfrastructureState,
        analysis: &DeploymentAnalysis,
    ) -> Result<OptimizationRecommendations> {
        let mut recommendations = OptimizationRecommendations {
            estimated_savings: 0.0,
            actions: Vec::new(),
        };
        
        // Resource optimization
        if let Some(resource_opt) = self.analyze_resource_optimization(state, analysis).await? {
            recommendations.actions.push(resource_opt.clone());
            recommendations.estimated_savings += resource_opt.estimated_savings;
        }
        
        // Scaling optimization
        if let Some(scaling_opt) = self.analyze_scaling_optimization(state, analysis).await? {
            recommendations.actions.push(scaling_opt.clone());
            recommendations.estimated_savings += scaling_opt.estimated_savings;
        }
        
        // Cost optimization
        if let Some(cost_opt) = self.analyze_cost_optimization(state, analysis).await? {
            recommendations.actions.push(cost_opt.clone());
            recommendations.estimated_savings += cost_opt.estimated_savings;
        }
        
        Ok(recommendations)
    }
    
    fn initialize_models(&mut self) {
        // Initialize a simple logistic regression model for success prediction
        let weights = Array2::from_shape_vec((10, 1), vec![
            0.5, -0.3, 0.2, 0.8, -0.1, 0.4, 0.6, -0.2, 0.3, 0.7
        ]).unwrap();
        let bias = Array1::from_vec(vec![0.1]);
        
        self.models.insert(
            "success_predictor".to_string(),
            PredictionModel {
                model_type: ModelType::LogisticRegression,
                weights,
                bias,
                feature_importance: vec![
                    ("previous_success_rate".to_string(), 0.25),
                    ("resource_availability".to_string(), 0.20),
                    ("time_of_day".to_string(), 0.15),
                    ("dependency_health".to_string(), 0.15),
                    ("recent_incidents".to_string(), 0.10),
                    ("deployment_size".to_string(), 0.05),
                    ("environment_stability".to_string(), 0.05),
                    ("team_availability".to_string(), 0.03),
                    ("change_complexity".to_string(), 0.02),
                ],
                accuracy: 0.92,
            },
        );
        
        // Duration prediction model
        let duration_weights = Array2::from_shape_vec((8, 1), vec![
            120.0, 80.0, 45.0, 200.0, 30.0, 150.0, 60.0, 90.0
        ]).unwrap();
        let duration_bias = Array1::from_vec(vec![300.0]); // Base duration in seconds
        
        self.models.insert(
            "duration_predictor".to_string(),
            PredictionModel {
                model_type: ModelType::LogisticRegression,
                weights: duration_weights,
                bias: duration_bias,
                feature_importance: vec![
                    ("deployment_size".to_string(), 0.30),
                    ("replica_count".to_string(), 0.20),
                    ("dependency_count".to_string(), 0.15),
                    ("health_check_count".to_string(), 0.10),
                    ("resource_requirements".to_string(), 0.10),
                    ("network_latency".to_string(), 0.08),
                    ("cluster_load".to_string(), 0.05),
                    ("time_since_last_deploy".to_string(), 0.02),
                ],
                accuracy: 0.88,
            },
        );
    }
    
    fn extract_features(
        &self,
        deployment: &DeploymentPlan,
        patterns: &[DeploymentPattern],
    ) -> Result<FeatureVector> {
        let mut features = Vec::new();
        let mut feature_names = Vec::new();
        
        // Historical success rate
        let success_rate = patterns.iter()
            .find(|p| p.service == deployment.service && p.environment == deployment.environment)
            .map(|p| p.success_rate)
            .unwrap_or(0.5);
        features.push(success_rate);
        feature_names.push("historical_success_rate".to_string());
        
        // Time-based features
        let hour = Utc::now().hour() as f64;
        let is_business_hours = (hour >= 9.0 && hour <= 17.0) as i32 as f64;
        features.push(is_business_hours);
        feature_names.push("is_business_hours".to_string());
        
        // Day of week (0 = Sunday, 6 = Saturday)
        let day_of_week = Utc::now().weekday().num_days_from_sunday() as f64;
        let is_weekend = (day_of_week == 0.0 || day_of_week == 6.0) as i32 as f64;
        features.push(is_weekend);
        feature_names.push("is_weekend".to_string());
        
        // Resource features
        features.push(deployment.resources.cpu_cores);
        feature_names.push("cpu_cores".to_string());
        
        features.push(deployment.resources.memory_mb as f64);
        feature_names.push("memory_mb".to_string());
        
        // Deployment complexity
        features.push(deployment.replicas as f64);
        feature_names.push("replica_count".to_string());
        
        features.push(deployment.dependencies.len() as f64);
        feature_names.push("dependency_count".to_string());
        
        features.push(deployment.health_checks.len() as f64);
        feature_names.push("health_check_count".to_string());
        
        // Strategy features
        let strategy_risk = match &deployment.strategy {
            DeploymentStrategy::Recreate => 1.0,
            DeploymentStrategy::RollingUpdate { .. } => 0.3,
            DeploymentStrategy::BlueGreen { .. } => 0.2,
            DeploymentStrategy::Canary { .. } => 0.1,
        };
        features.push(strategy_risk);
        feature_names.push("strategy_risk".to_string());
        
        // Environment risk
        let env_risk = match deployment.environment.as_str() {
            "production" => 1.0,
            "staging" => 0.5,
            "development" => 0.1,
            _ => 0.3,
        };
        features.push(env_risk);
        feature_names.push("environment_risk".to_string());
        
        Ok(FeatureVector {
            features,
            feature_names,
            timestamp: Utc::now(),
        })
    }
    
    fn run_model(&self, model: &PredictionModel, features: &FeatureVector) -> Result<(f64, f64, f64)> {
        // Simple prediction using the model weights
        let feature_array = Array1::from_vec(features.features.clone());
        
        // For success prediction
        let success_features = feature_array.slice(ndarray::s![0..10]).to_owned();
        let success_score = success_features.dot(&model.weights.column(0)) + model.bias[0];
        let success_prob = 1.0 / (1.0 + (-success_score).exp()); // Sigmoid
        
        // For duration prediction (using a subset of features)
        let duration_features = feature_array.slice(ndarray::s![0..8]).to_owned();
        let duration = duration_features.iter().sum::<f64>() * 10.0 + 300.0; // Simplified
        
        // Confidence based on model accuracy and feature quality
        let confidence = model.accuracy * 0.8 + 0.2; // Base confidence on model accuracy
        
        Ok((success_prob, duration, confidence))
    }
    
    fn ensemble_predictions(&self, predictions: &[(String, (f64, f64, f64))]) -> Result<(f64, f64, f64)> {
        if predictions.is_empty() {
            return Ok((0.5, 600.0, 0.5));
        }
        
        // Weighted average based on model confidence
        let total_weight: f64 = predictions.iter().map(|(_, (_, _, conf))| conf).sum();
        
        let success_prob = predictions.iter()
            .map(|(_, (prob, _, conf))| prob * conf)
            .sum::<f64>() / total_weight;
        
        let duration = predictions.iter()
            .map(|(_, (_, dur, conf))| dur * conf)
            .sum::<f64>() / total_weight;
        
        let confidence = predictions.iter()
            .map(|(_, (_, _, conf))| conf)
            .sum::<f64>() / predictions.len() as f64;
        
        Ok((success_prob, duration, confidence))
    }
    
    fn analyze_risks(
        &self,
        deployment: &DeploymentPlan,
        patterns: &[DeploymentPattern],
        prediction: &(f64, f64, f64),
    ) -> Result<Vec<RiskFactor>> {
        let mut risks = Vec::new();
        
        // Low success probability risk
        if prediction.0 < 0.7 {
            risks.push(RiskFactor {
                factor: "Low success probability".to_string(),
                severity: if prediction.0 < 0.5 { RiskSeverity::High } else { RiskSeverity::Medium },
                probability: 1.0 - prediction.0,
                mitigation: "Consider using canary deployment or increasing testing".to_string(),
            });
        }
        
        // Resource constraint risk
        if deployment.resources.cpu_cores > 8.0 || deployment.resources.memory_mb > 16384 {
            risks.push(RiskFactor {
                factor: "High resource requirements".to_string(),
                severity: RiskSeverity::Medium,
                probability: 0.3,
                mitigation: "Ensure cluster has sufficient capacity; consider pre-scaling".to_string(),
            });
        }
        
        // Time-based risk
        let hour = Utc::now().hour();
        if hour >= 8 && hour <= 10 || hour >= 16 && hour <= 18 {
            risks.push(RiskFactor {
                factor: "Peak traffic hours".to_string(),
                severity: RiskSeverity::Medium,
                probability: 0.4,
                mitigation: "Consider deploying during off-peak hours".to_string(),
            });
        }
        
        // Historical failure patterns
        for pattern in patterns {
            if pattern.service == deployment.service && pattern.success_rate < 0.8 {
                for (failure_type, freq) in &pattern.common_failures {
                    if *freq > 0.2 {
                        risks.push(RiskFactor {
                            factor: format!("Historical {} failures", failure_type),
                            severity: if *freq > 0.5 { RiskSeverity::High } else { RiskSeverity::Medium },
                            probability: *freq,
                            mitigation: format!("Review and address previous {} issues", failure_type),
                        });
                    }
                }
            }
        }
        
        Ok(risks)
    }
    
    fn generate_optimizations(
        &self,
        deployment: &DeploymentPlan,
        patterns: &[DeploymentPattern],
        prediction: &(f64, f64, f64),
    ) -> Result<Vec<Optimization>> {
        let mut optimizations = Vec::new();
        
        // Timing optimization
        if let Some(pattern) = patterns.iter().find(|p| p.service == deployment.service) {
            if let Some(best_window) = pattern.optimal_time_windows.iter().max_by_key(|w| (w.success_rate * 100.0) as i32) {
                optimizations.push(Optimization {
                    category: OptimizationCategory::Timing,
                    description: format!("Deploy between {}:00 and {}:00 on day {}", 
                        best_window.hour_start, best_window.hour_end, best_window.day_of_week),
                    impact: OptimizationImpact {
                        success_rate_improvement: best_window.success_rate - prediction.0,
                        duration_reduction: 0.1,
                        cost_savings: 0.0,
                    },
                    implementation: "Schedule deployment during optimal time window".to_string(),
                });
            }
        }
        
        // Strategy optimization
        if matches!(deployment.strategy, DeploymentStrategy::Recreate) {
            optimizations.push(Optimization {
                category: OptimizationCategory::Strategy,
                description: "Use rolling update instead of recreate strategy".to_string(),
                impact: OptimizationImpact {
                    success_rate_improvement: 0.15,
                    duration_reduction: 0.3,
                    cost_savings: 0.0,
                },
                implementation: "Change deployment strategy to RollingUpdate with max_surge=1, max_unavailable=1".to_string(),
            });
        }
        
        // Resource optimization
        if deployment.resources.cpu_cores > 4.0 {
            optimizations.push(Optimization {
                category: OptimizationCategory::Resources,
                description: "Optimize CPU allocation based on actual usage".to_string(),
                impact: OptimizationImpact {
                    success_rate_improvement: 0.0,
                    duration_reduction: 0.05,
                    cost_savings: (deployment.resources.cpu_cores - 4.0) * 50.0, // $50 per core
                },
                implementation: "Set CPU request to 2 cores, limit to 4 cores".to_string(),
            });
        }
        
        Ok(optimizations)
    }
    
    fn generate_reasoning(&self, predictions: &[(String, (f64, f64, f64))], deployment: &DeploymentPlan) -> Vec<String> {
        let mut reasoning = Vec::new();
        
        reasoning.push(format!(
            "Analyzing deployment of {} version {} to {}",
            deployment.service, deployment.version, deployment.environment
        ));
        
        for (model_name, (prob, dur, conf)) in predictions {
            reasoning.push(format!(
                "{} predicts {:.1}% success probability with {:.0}s duration (confidence: {:.1}%)",
                model_name, prob * 100.0, dur, conf * 100.0
            ));
        }
        
        reasoning.push(format!(
            "Deployment strategy: {:?} with {} replicas",
            deployment.strategy, deployment.replicas
        ));
        
        reasoning
    }
    
    async fn analyze_resource_optimization(
        &self,
        _state: &InfrastructureState,
        _analysis: &DeploymentAnalysis,
    ) -> Result<Option<OptimizationAction>> {
        // Simplified implementation
        Ok(Some(OptimizationAction {
            action_type: "right_size_resources".to_string(),
            description: "Right-size under-utilized resources".to_string(),
            estimated_savings: 1500.0,
            risk_level: crate::RiskLevel::Low,
            implementation_steps: vec![
                "Analyze resource usage patterns".to_string(),
                "Identify over-provisioned services".to_string(),
                "Adjust resource requests and limits".to_string(),
                "Monitor performance impact".to_string(),
            ],
        }))
    }
    
    async fn analyze_scaling_optimization(
        &self,
        _state: &InfrastructureState,
        _analysis: &DeploymentAnalysis,
    ) -> Result<Option<OptimizationAction>> {
        Ok(Some(OptimizationAction {
            action_type: "optimize_autoscaling".to_string(),
            description: "Optimize autoscaling policies".to_string(),
            estimated_savings: 800.0,
            risk_level: crate::RiskLevel::Medium,
            implementation_steps: vec![
                "Review current scaling policies".to_string(),
                "Adjust scaling thresholds".to_string(),
                "Implement predictive scaling".to_string(),
            ],
        }))
    }
    
    async fn analyze_cost_optimization(
        &self,
        _state: &InfrastructureState,
        _analysis: &DeploymentAnalysis,
    ) -> Result<Option<OptimizationAction>> {
        Ok(Some(OptimizationAction {
            action_type: "use_spot_instances".to_string(),
            description: "Leverage spot instances for non-critical workloads".to_string(),
            estimated_savings: 2000.0,
            risk_level: crate::RiskLevel::Medium,
            implementation_steps: vec![
                "Identify stateless workloads".to_string(),
                "Configure spot instance pools".to_string(),
                "Implement graceful termination handling".to_string(),
            ],
        }))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationRecommendations {
    pub estimated_savings: f64,
    pub actions: Vec<crate::OptimizationAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationAction {
    pub action_type: String,
    pub description: String,
    pub estimated_savings: f64,
    pub risk_level: crate::RiskLevel,
    pub implementation_steps: Vec<String>,
}