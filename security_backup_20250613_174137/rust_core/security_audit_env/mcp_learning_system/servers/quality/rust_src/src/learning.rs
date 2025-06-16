use ahash::AHashMap;
use dashmap::DashMap;
use parking_lot::RwLock;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningModel {
    pub model_type: ModelType,
    pub weights: Vec<f64>,
    pub features: Vec<String>,
    pub accuracy: f64,
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModelType {
    TestFailurePredictor,
    CoverageOptimizer,
    PerformancePredictor,
    QualityClassifier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingData {
    pub inputs: Vec<Vec<f64>>,
    pub outputs: Vec<f64>,
    pub timestamps: Vec<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictionResult {
    pub value: f64,
    pub confidence: f64,
    pub explanation: Option<String>,
}

pub struct QualityLearningSystem {
    models: Arc<DashMap<ModelType, LearningModel>>,
    training_data: Arc<DashMap<ModelType, TrainingData>>,
    feature_importance: Arc<RwLock<HashMap<String, f64>>>,
    learning_rate: f64,
    momentum: f64,
}

impl QualityLearningSystem {
    pub fn new() -> Self {
        let mut system = Self {
            models: Arc::new(DashMap::new()),
            training_data: Arc::new(DashMap::new()),
            feature_importance: Arc::new(RwLock::new(HashMap::new())),
            learning_rate: 0.01,
            momentum: 0.9,
        };
        
        // Initialize models
        system.initialize_models();
        
        system
    }
    
    pub async fn train(&self, model_type: ModelType, data: TrainingData) -> Result<(), LearningError> {
        info!("Training {:?} model with {} samples", model_type, data.inputs.len());
        
        // Store training data
        self.training_data.insert(model_type.clone(), data.clone());
        
        // Get or create model
        let mut model = self.models.entry(model_type.clone())
            .or_insert_with(|| self.create_model(&model_type));
        
        // Train using gradient descent
        let epochs = 100;
        let batch_size = 32;
        
        for epoch in 0..epochs {
            let mut total_loss = 0.0;
            
            // Mini-batch training
            for batch in data.inputs.chunks(batch_size) {
                let batch_outputs = &data.outputs[0..batch.len()];
                let loss = self.train_batch(&mut model, batch, batch_outputs)?;
                total_loss += loss;
            }
            
            let avg_loss = total_loss / (data.inputs.len() as f64 / batch_size as f64);
            
            if epoch % 10 == 0 {
                debug!("Epoch {}: avg loss = {:.4}", epoch, avg_loss);
            }
            
            // Early stopping
            if avg_loss < 0.01 {
                break;
            }
        }
        
        // Update model accuracy
        model.accuracy = self.evaluate_model(&model, &data);
        model.last_updated = chrono::Utc::now();
        
        // Update feature importance
        self.update_feature_importance(&model);
        
        info!("Training complete. Model accuracy: {:.2}%", model.accuracy * 100.0);
        
        Ok(())
    }
    
    pub async fn predict(&self, model_type: ModelType, features: Vec<f64>) -> Result<PredictionResult, LearningError> {
        let model = self.models.get(&model_type)
            .ok_or(LearningError::ModelNotFound)?;
        
        // Validate features
        if features.len() != model.weights.len() {
            return Err(LearningError::InvalidFeatures);
        }
        
        // Make prediction
        let value = self.forward_pass(&model.weights, &features);
        
        // Calculate confidence based on feature importance
        let confidence = self.calculate_confidence(&features, &model);
        
        // Generate explanation
        let explanation = self.generate_explanation(&features, &model, value);
        
        Ok(PredictionResult {
            value,
            confidence,
            explanation,
        })
    }
    
    pub async fn update_online(&self, model_type: ModelType, features: Vec<f64>, actual: f64) -> Result<(), LearningError> {
        let mut model = self.models.get_mut(&model_type)
            .ok_or(LearningError::ModelNotFound)?;
        
        // Online learning update
        let prediction = self.forward_pass(&model.weights, &features);
        let error = actual - prediction;
        
        // Update weights using gradient descent
        for (i, weight) in model.weights.iter_mut().enumerate() {
            let gradient = error * features.get(i).unwrap_or(&0.0);
            *weight += self.learning_rate * gradient;
        }
        
        // Update training data
        if let Some(mut data) = self.training_data.get_mut(&model_type) {
            data.inputs.push(features);
            data.outputs.push(actual);
            data.timestamps.push(chrono::Utc::now());
            
            // Keep only recent data (last 10000 samples)
            if data.inputs.len() > 10000 {
                data.inputs.remove(0);
                data.outputs.remove(0);
                data.timestamps.remove(0);
            }
        }
        
        Ok(())
    }
    
    pub fn get_feature_importance(&self) -> HashMap<String, f64> {
        self.feature_importance.read().clone()
    }
    
    pub fn get_model_metrics(&self, model_type: &ModelType) -> Option<ModelMetrics> {
        let model = self.models.get(model_type)?;
        let data = self.training_data.get(model_type)?;
        
        Some(ModelMetrics {
            accuracy: model.accuracy,
            sample_count: data.inputs.len(),
            last_updated: model.last_updated,
            feature_count: model.features.len(),
        })
    }
    
    fn initialize_models(&mut self) {
        // Test Failure Predictor
        self.models.insert(
            ModelType::TestFailurePredictor,
            LearningModel {
                model_type: ModelType::TestFailurePredictor,
                weights: vec![0.0; 10], // 10 features
                features: vec![
                    "file_changes".to_string(),
                    "code_complexity".to_string(),
                    "test_history".to_string(),
                    "coverage_impact".to_string(),
                    "dependency_changes".to_string(),
                    "previous_failures".to_string(),
                    "time_since_last_run".to_string(),
                    "test_duration".to_string(),
                    "flakiness_score".to_string(),
                    "critical_path".to_string(),
                ],
                accuracy: 0.0,
                last_updated: chrono::Utc::now(),
            },
        );
        
        // Coverage Optimizer
        self.models.insert(
            ModelType::CoverageOptimizer,
            LearningModel {
                model_type: ModelType::CoverageOptimizer,
                weights: vec![0.0; 8],
                features: vec![
                    "current_coverage".to_string(),
                    "uncovered_lines".to_string(),
                    "branch_coverage".to_string(),
                    "complexity".to_string(),
                    "test_count".to_string(),
                    "file_size".to_string(),
                    "change_frequency".to_string(),
                    "bug_density".to_string(),
                ],
                accuracy: 0.0,
                last_updated: chrono::Utc::now(),
            },
        );
        
        // Performance Predictor
        self.models.insert(
            ModelType::PerformancePredictor,
            LearningModel {
                model_type: ModelType::PerformancePredictor,
                weights: vec![0.0; 12],
                features: vec![
                    "algorithm_complexity".to_string(),
                    "data_size".to_string(),
                    "memory_allocations".to_string(),
                    "io_operations".to_string(),
                    "cpu_usage".to_string(),
                    "cache_misses".to_string(),
                    "thread_count".to_string(),
                    "lock_contention".to_string(),
                    "network_calls".to_string(),
                    "database_queries".to_string(),
                    "code_size".to_string(),
                    "optimization_level".to_string(),
                ],
                accuracy: 0.0,
                last_updated: chrono::Utc::now(),
            },
        );
        
        // Quality Classifier
        self.models.insert(
            ModelType::QualityClassifier,
            LearningModel {
                model_type: ModelType::QualityClassifier,
                weights: vec![0.0; 15],
                features: vec![
                    "cyclomatic_complexity".to_string(),
                    "cognitive_complexity".to_string(),
                    "code_duplication".to_string(),
                    "test_coverage".to_string(),
                    "documentation_coverage".to_string(),
                    "dependency_count".to_string(),
                    "coupling".to_string(),
                    "cohesion".to_string(),
                    "code_smells".to_string(),
                    "security_issues".to_string(),
                    "performance_issues".to_string(),
                    "maintainability_index".to_string(),
                    "technical_debt".to_string(),
                    "code_age".to_string(),
                    "contributor_count".to_string(),
                ],
                accuracy: 0.0,
                last_updated: chrono::Utc::now(),
            },
        );
    }
    
    fn create_model(&self, model_type: &ModelType) -> LearningModel {
        match model_type {
            ModelType::TestFailurePredictor => {
                LearningModel {
                    model_type: model_type.clone(),
                    weights: vec![0.0; 10],
                    features: vec!["feature".to_string(); 10],
                    accuracy: 0.0,
                    last_updated: chrono::Utc::now(),
                }
            }
            _ => {
                LearningModel {
                    model_type: model_type.clone(),
                    weights: vec![0.0; 8],
                    features: vec!["feature".to_string(); 8],
                    accuracy: 0.0,
                    last_updated: chrono::Utc::now(),
                }
            }
        }
    }
    
    fn train_batch(
        &self,
        model: &mut LearningModel,
        inputs: &[Vec<f64>],
        outputs: &[f64],
    ) -> Result<f64, LearningError> {
        let mut total_loss = 0.0;
        
        for (input, &target) in inputs.iter().zip(outputs.iter()) {
            // Forward pass
            let prediction = self.forward_pass(&model.weights, input);
            let error = target - prediction;
            total_loss += error * error;
            
            // Backward pass (gradient descent)
            for (i, weight) in model.weights.iter_mut().enumerate() {
                let gradient = -2.0 * error * input.get(i).unwrap_or(&0.0);
                *weight -= self.learning_rate * gradient;
            }
        }
        
        Ok(total_loss / inputs.len() as f64)
    }
    
    fn forward_pass(&self, weights: &[f64], inputs: &[f64]) -> f64 {
        // Simple linear model with sigmoid activation
        let linear: f64 = weights.iter()
            .zip(inputs.iter())
            .map(|(w, x)| w * x)
            .sum();
        
        // Sigmoid activation
        1.0 / (1.0 + (-linear).exp())
    }
    
    fn evaluate_model(&self, model: &LearningModel, data: &TrainingData) -> f64 {
        if data.inputs.is_empty() {
            return 0.0;
        }
        
        let mut correct = 0;
        
        for (input, &target) in data.inputs.iter().zip(data.outputs.iter()) {
            let prediction = self.forward_pass(&model.weights, input);
            let predicted_class = if prediction > 0.5 { 1.0 } else { 0.0 };
            let target_class = if target > 0.5 { 1.0 } else { 0.0 };
            
            if predicted_class == target_class {
                correct += 1;
            }
        }
        
        correct as f64 / data.inputs.len() as f64
    }
    
    fn update_feature_importance(&self, model: &LearningModel) {
        let mut importance = self.feature_importance.write();
        
        // Calculate importance based on weight magnitudes
        let total_weight: f64 = model.weights.iter().map(|w| w.abs()).sum();
        
        for (i, feature_name) in model.features.iter().enumerate() {
            if let Some(weight) = model.weights.get(i) {
                let feature_importance = weight.abs() / total_weight;
                importance.insert(feature_name.clone(), feature_importance);
            }
        }
    }
    
    fn calculate_confidence(&self, features: &[f64], model: &LearningModel) -> f64 {
        // Base confidence on feature values and model accuracy
        let feature_confidence: f64 = features.iter()
            .map(|f| (f.abs() - 0.5).abs() * 2.0) // Higher confidence for extreme values
            .sum::<f64>() / features.len() as f64;
        
        (model.accuracy + feature_confidence) / 2.0
    }
    
    fn generate_explanation(
        &self,
        features: &[f64],
        model: &LearningModel,
        prediction: f64,
    ) -> Option<String> {
        let importance = self.feature_importance.read();
        
        // Find most important features
        let mut feature_impacts: Vec<(String, f64)> = model.features.iter()
            .enumerate()
            .filter_map(|(i, name)| {
                let weight = model.weights.get(i)?;
                let value = features.get(i)?;
                let impact = weight * value;
                let importance = importance.get(name).unwrap_or(&0.0);
                Some((name.clone(), impact * importance))
            })
            .collect();
        
        feature_impacts.sort_by(|a, b| b.1.abs().partial_cmp(&a.1.abs()).unwrap());
        
        if feature_impacts.is_empty() {
            return None;
        }
        
        let top_features: Vec<String> = feature_impacts.iter()
            .take(3)
            .map(|(name, impact)| {
                if *impact > 0.0 {
                    format!("{} (positive impact)", name)
                } else {
                    format!("{} (negative impact)", name)
                }
            })
            .collect();
        
        Some(format!(
            "Prediction {:.2} based primarily on: {}",
            prediction,
            top_features.join(", ")
        ))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LearningError {
    #[error("Model not found")]
    ModelNotFound,
    
    #[error("Invalid features provided")]
    InvalidFeatures,
    
    #[error("Training failed: {0}")]
    TrainingFailed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetrics {
    pub accuracy: f64,
    pub sample_count: usize,
    pub last_updated: chrono::DateTime<chrono::Utc>,
    pub feature_count: usize,
}

// Pattern recognition for quality issues
pub struct QualityPatternRecognizer {
    patterns: Arc<DashMap<String, QualityPattern>>,
    pattern_matcher: Arc<PatternMatcher>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityPattern {
    pub name: String,
    pub pattern_type: String,
    pub indicators: Vec<String>,
    pub frequency: f64,
    pub impact: f64,
}

struct PatternMatcher {
    rules: Vec<MatchRule>,
}

#[derive(Clone)]
struct MatchRule {
    name: String,
    condition: fn(&HashMap<String, f64>) -> bool,
    impact: f64,
}

impl QualityPatternRecognizer {
    pub fn new() -> Self {
        Self {
            patterns: Arc::new(DashMap::new()),
            pattern_matcher: Arc::new(PatternMatcher::new()),
        }
    }
    
    pub async fn recognize_patterns(&self, metrics: HashMap<String, f64>) -> Vec<QualityPattern> {
        let mut recognized = Vec::new();
        
        // Apply matching rules
        for rule in &self.pattern_matcher.rules {
            if (rule.condition)(&metrics) {
                let pattern = QualityPattern {
                    name: rule.name.clone(),
                    pattern_type: "detected".to_string(),
                    indicators: metrics.keys().cloned().collect(),
                    frequency: 1.0,
                    impact: rule.impact,
                };
                
                recognized.push(pattern.clone());
                
                // Update pattern database
                self.patterns
                    .entry(rule.name.clone())
                    .and_modify(|p| p.frequency += 1.0)
                    .or_insert(pattern);
            }
        }
        
        recognized
    }
    
    pub fn get_pattern_history(&self, pattern_name: &str) -> Option<QualityPattern> {
        self.patterns.get(pattern_name).map(|p| p.clone())
    }
}

impl PatternMatcher {
    fn new() -> Self {
        Self {
            rules: vec![
                MatchRule {
                    name: "high_complexity".to_string(),
                    condition: |metrics| {
                        metrics.get("complexity").unwrap_or(&0.0) > &20.0
                    },
                    impact: 0.8,
                },
                MatchRule {
                    name: "low_coverage".to_string(),
                    condition: |metrics| {
                        metrics.get("coverage").unwrap_or(&1.0) < &0.7
                    },
                    impact: 0.7,
                },
                MatchRule {
                    name: "performance_regression".to_string(),
                    condition: |metrics| {
                        metrics.get("execution_time").unwrap_or(&0.0) > &1000.0
                    },
                    impact: 0.9,
                },
            ],
        }
    }
}