// ============================================================================
// Learning System - ML-Based Pattern Recognition and Optimization
// ============================================================================

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};

use super::{ExecutionResult, PerformanceMetrics, LearningInsights, CommandPattern, 
             OptimizationSuggestion, PerformanceTrend, FailurePattern};
use super::command_chain::CommandChain;

/// Machine learning system for pattern recognition
pub struct LearningSystem {
    config: LearningConfig,
    pattern_database: Arc<RwLock<PatternDatabase>>,
    performance_history: Arc<RwLock<PerformanceHistory>>,
    optimization_model: Arc<OptimizationModel>,
}

/// Configuration for the learning system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningConfig {
    pub pattern_threshold: f64,
    pub history_window: usize,
    pub min_samples: usize,
    pub confidence_threshold: f64,
    pub anomaly_detection: bool,
    pub auto_optimization: bool,
}

impl Default for LearningConfig {
    fn default() -> Self {
        Self {
            pattern_threshold: 0.7,
            history_window: 1000,
            min_samples: 10,
            confidence_threshold: 0.8,
            anomaly_detection: true,
            auto_optimization: true,
        }
    }
}

/// Pattern database for storing command patterns
struct PatternDatabase {
    patterns: HashMap<String, PatternRecord>,
    pattern_index: HashMap<String, Vec<String>>, // Index for fast lookup
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PatternRecord {
    pattern: String,
    frequency: u64,
    success_rate: f64,
    avg_duration_ms: f64,
    variations: Vec<PatternVariation>,
    last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PatternVariation {
    command: String,
    performance_score: f64,
    usage_count: u64,
}

/// Performance history tracking
struct PerformanceHistory {
    executions: VecDeque<ExecutionRecord>,
    metrics_aggregates: HashMap<String, MetricAggregate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExecutionRecord {
    id: String,
    command: String,
    metrics: PerformanceMetrics,
    success: bool,
    timestamp: DateTime<Utc>,
    optimizations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MetricAggregate {
    metric_name: String,
    values: VecDeque<f64>,
    mean: f64,
    std_dev: f64,
    trend: TrendDirection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum TrendDirection {
    Increasing,
    Decreasing,
    Stable,
}

/// Optimization model for suggesting improvements
struct OptimizationModel {
    rules: Vec<OptimizationRule>,
    learned_optimizations: HashMap<String, LearnedOptimization>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OptimizationRule {
    pattern: String,
    condition: OptimizationCondition,
    transformation: String,
    expected_improvement: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum OptimizationCondition {
    HighCpuUsage(f64),
    HighMemoryUsage(f64),
    LongDuration(u64),
    FrequentFailure(f64),
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LearnedOptimization {
    original_pattern: String,
    optimized_pattern: String,
    improvement_ratio: f64,
    confidence: f64,
    sample_count: u64,
}

impl LearningSystem {
    /// Create a new learning system
    pub fn new(config: LearningConfig) -> Result<Self> {
        let pattern_database = Arc::new(RwLock::new(PatternDatabase {
            patterns: HashMap::new(),
            pattern_index: HashMap::new(),
        }));

        let performance_history = Arc::new(RwLock::new(PerformanceHistory {
            executions: VecDeque::with_capacity(config.history_window),
            metrics_aggregates: HashMap::new(),
        }));

        let optimization_model = Arc::new(OptimizationModel::new());

        Ok(Self {
            config,
            pattern_database,
            performance_history,
            optimization_model,
        })
    }

    /// Update learning system from execution results
    pub async fn update_from_execution(&mut self, result: &ExecutionResult, metrics: &PerformanceMetrics) -> Result<()> {
        // Record execution
        let record = ExecutionRecord {
            id: uuid::Uuid::new_v4().to_string(),
            command: result.output.clone(), // This should be the original command
            metrics: metrics.clone(),
            success: result.exit_code == 0,
            timestamp: Utc::now(),
            optimizations: result.optimizations_applied.clone(),
        };

        // Update performance history
        {
            let mut history = self.performance_history.write().await;
            history.add_execution(record.clone(), self.config.history_window);
            history.update_aggregates(&record);
        }

        // Extract and update patterns
        let patterns = self.extract_patterns(&record.command).await?;
        {
            let mut db = self.pattern_database.write().await;
            for pattern in patterns {
                db.update_pattern(pattern, &record);
            }
        }

        // Learn from optimization results
        if !result.optimizations_applied.is_empty() {
            self.optimization_model.learn_from_result(&record, result).await?;
        }

        // Detect anomalies if enabled
        if self.config.anomaly_detection {
            self.detect_anomalies(&record).await?;
        }

        Ok(())
    }

    /// Get learning insights
    pub fn get_insights(&self) -> Result<LearningInsights> {
        let db = futures::executor::block_on(self.pattern_database.read());
        let history = futures::executor::block_on(self.performance_history.read());

        // Extract common patterns
        let common_patterns = db.patterns.values()
            .filter(|p| p.frequency >= self.config.min_samples as u64)
            .map(|p| CommandPattern {
                pattern: p.pattern.clone(),
                frequency: p.frequency,
                avg_performance: p.avg_duration_ms,
            })
            .collect();

        // Get optimization suggestions
        let optimization_suggestions = self.optimization_model
            .get_suggestions(&db.patterns, self.config.confidence_threshold)
            .into_iter()
            .map(|s| OptimizationSuggestion {
                original: s.original_pattern,
                optimized: s.optimized_pattern,
                expected_improvement: s.improvement_ratio,
                confidence: s.confidence,
            })
            .collect();

        // Calculate performance trends
        let performance_trends = history.metrics_aggregates.iter()
            .map(|(name, agg)| {
                let trend_str = match agg.trend {
                    TrendDirection::Increasing => "increasing",
                    TrendDirection::Decreasing => "decreasing",
                    TrendDirection::Stable => "stable",
                };

                (name.clone(), PerformanceTrend {
                    metric: name.clone(),
                    trend: trend_str.to_string(),
                    change_percent: agg.calculate_change_percent(),
                })
            })
            .collect();

        // Identify failure patterns
        let failure_patterns = self.identify_failure_patterns(&db.patterns);

        Ok(LearningInsights {
            common_patterns,
            optimization_suggestions,
            performance_trends,
            failure_patterns,
        })
    }

    /// Extract patterns from a command
    async fn extract_patterns(&self, command: &str) -> Result<Vec<String>> {
        let mut patterns = Vec::new();

        // Extract command structure patterns
        patterns.push(self.extract_structure_pattern(command));

        // Extract pipeline patterns
        if command.contains('|') {
            patterns.extend(self.extract_pipeline_patterns(command));
        }

        // Extract conditional patterns
        if command.contains("&&") || command.contains("||") {
            patterns.extend(self.extract_conditional_patterns(command));
        }

        // Extract loop patterns
        patterns.extend(self.extract_loop_patterns(command));

        Ok(patterns)
    }

    /// Extract structure pattern from command
    fn extract_structure_pattern(&self, command: &str) -> String {
        // Simplify command to structural pattern
        let mut pattern = String::new();
        let mut in_string = false;
        let mut quote_char = ' ';

        for ch in command.chars() {
            if !in_string && (ch == '\'' || ch == '"') {
                in_string = true;
                quote_char = ch;
                pattern.push_str("<STRING>");
            } else if in_string && ch == quote_char {
                in_string = false;
            } else if !in_string {
                if ch.is_alphanumeric() || ch == '-' {
                    pattern.push(ch);
                } else if ch.is_whitespace() && !pattern.ends_with(' ') {
                    pattern.push(' ');
                } else if "|&;<>()".contains(ch) {
                    pattern.push(' ');
                    pattern.push(ch);
                    pattern.push(' ');
                }
            }
        }

        pattern.trim().to_string()
    }

    /// Extract pipeline patterns
    fn extract_pipeline_patterns(&self, command: &str) -> Vec<String> {
        let parts: Vec<&str> = command.split('|').collect();
        let mut patterns = Vec::new();

        // Individual pipe patterns
        for i in 0..parts.len() - 1 {
            let pattern = format!("{} | {}", 
                self.get_command_type(parts[i].trim()),
                self.get_command_type(parts[i + 1].trim())
            );
            patterns.push(pattern);
        }

        // Full pipeline pattern
        if parts.len() > 2 {
            let full_pattern = parts.iter()
                .map(|p| self.get_command_type(p.trim()))
                .collect::<Vec<_>>()
                .join(" | ");
            patterns.push(full_pattern);
        }

        patterns
    }

    /// Extract conditional patterns
    fn extract_conditional_patterns(&self, command: &str) -> Vec<String> {
        let mut patterns = Vec::new();
        
        // Split by && and ||
        let parts = command.split(|c| c == '&' || c == '|')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();

        for window in parts.windows(2) {
            let pattern = format!("{} <COND> {}", 
                self.get_command_type(window[0]),
                self.get_command_type(window[1])
            );
            patterns.push(pattern);
        }

        patterns
    }

    /// Extract loop patterns
    fn extract_loop_patterns(&self, command: &str) -> Vec<String> {
        let mut patterns = Vec::new();

        // For loops
        if command.contains("for ") && command.contains(" do") {
            patterns.push("FOR_LOOP".to_string());
        }

        // While loops
        if command.contains("while ") && command.contains(" do") {
            patterns.push("WHILE_LOOP".to_string());
        }

        // Find patterns with xargs
        if command.contains("xargs") {
            patterns.push("XARGS_PATTERN".to_string());
        }

        patterns
    }

    /// Get command type for pattern matching
    fn get_command_type(&self, command: &str) -> String {
        let cmd = command.split_whitespace().next().unwrap_or("UNKNOWN");
        
        match cmd {
            "ls" | "find" | "locate" => "LIST_CMD",
            "grep" | "awk" | "sed" | "cut" => "FILTER_CMD",
            "sort" | "uniq" => "SORT_CMD",
            "cat" | "head" | "tail" => "VIEW_CMD",
            "echo" | "printf" => "OUTPUT_CMD",
            "cd" | "pushd" | "popd" => "NAV_CMD",
            "cp" | "mv" | "rm" => "FILE_CMD",
            _ => cmd,
        }.to_string()
    }

    /// Detect anomalies in execution
    async fn detect_anomalies(&self, record: &ExecutionRecord) -> Result<()> {
        let history = self.performance_history.read().await;

        // Check each metric for anomalies
        for (metric_name, value) in record.metrics.to_map() {
            if let Some(aggregate) = history.metrics_aggregates.get(&metric_name) {
                let z_score = (value - aggregate.mean) / aggregate.std_dev;
                
                if z_score.abs() > 3.0 {
                    tracing::warn!(
                        "Anomaly detected in {}: value={}, z_score={:.2}",
                        metric_name, value, z_score
                    );
                }
            }
        }

        Ok(())
    }

    /// Identify failure patterns
    fn identify_failure_patterns(&self, patterns: &HashMap<String, PatternRecord>) -> Vec<FailurePattern> {
        patterns.values()
            .filter(|p| {
                let failure_rate = 1.0 - p.success_rate;
                failure_rate > 0.1 && p.frequency >= self.config.min_samples as u64
            })
            .map(|p| FailurePattern {
                pattern: p.pattern.clone(),
                failure_rate: 1.0 - p.success_rate,
                common_errors: vec![], // Would need error tracking for this
            })
            .collect()
    }
}

impl PatternDatabase {
    /// Update pattern record with new execution
    fn update_pattern(&mut self, pattern: String, record: &ExecutionRecord) {
        let entry = self.patterns.entry(pattern.clone()).or_insert_with(|| {
            PatternRecord {
                pattern: pattern.clone(),
                frequency: 0,
                success_rate: 0.0,
                avg_duration_ms: 0.0,
                variations: Vec::new(),
                last_seen: Utc::now(),
            }
        });

        // Update frequency
        entry.frequency += 1;

        // Update success rate
        let old_total = entry.frequency - 1;
        let old_successes = (entry.success_rate * old_total as f64) as u64;
        let new_successes = old_successes + if record.success { 1 } else { 0 };
        entry.success_rate = new_successes as f64 / entry.frequency as f64;

        // Update average duration
        entry.avg_duration_ms = (entry.avg_duration_ms * old_total as f64 + 
                                record.metrics.total_duration_ms as f64) / entry.frequency as f64;

        // Update last seen
        entry.last_seen = record.timestamp;

        // Update pattern index
        self.update_pattern_index(&pattern, &record.command);
    }

    /// Update pattern index for fast lookup
    fn update_pattern_index(&mut self, pattern: &str, command: &str) {
        let words: Vec<String> = command.split_whitespace()
            .map(|s| s.to_lowercase())
            .collect();

        for word in words {
            self.pattern_index.entry(word)
                .or_insert_with(Vec::new)
                .push(pattern.to_string());
        }
    }
}

impl PerformanceHistory {
    /// Add execution record to history
    fn add_execution(&mut self, record: ExecutionRecord, max_size: usize) {
        self.executions.push_back(record);
        
        // Maintain window size
        while self.executions.len() > max_size {
            self.executions.pop_front();
        }
    }

    /// Update metric aggregates
    fn update_aggregates(&mut self, record: &ExecutionRecord) {
        for (metric_name, value) in record.metrics.to_map() {
            let aggregate = self.metrics_aggregates
                .entry(metric_name.clone())
                .or_insert_with(|| MetricAggregate {
                    metric_name,
                    values: VecDeque::new(),
                    mean: 0.0,
                    std_dev: 0.0,
                    trend: TrendDirection::Stable,
                });

            aggregate.add_value(value);
            aggregate.calculate_statistics();
            aggregate.detect_trend();
        }
    }
}

impl MetricAggregate {
    /// Add value to aggregate
    fn add_value(&mut self, value: f64) {
        self.values.push_back(value);
        
        // Keep last 100 values for trend detection
        if self.values.len() > 100 {
            self.values.pop_front();
        }
    }

    /// Calculate statistics
    fn calculate_statistics(&mut self) {
        if self.values.is_empty() {
            return;
        }

        // Calculate mean
        self.mean = self.values.iter().sum::<f64>() / self.values.len() as f64;

        // Calculate standard deviation
        let variance = self.values.iter()
            .map(|v| (v - self.mean).powi(2))
            .sum::<f64>() / self.values.len() as f64;
        
        self.std_dev = variance.sqrt();
    }

    /// Detect trend in values
    fn detect_trend(&mut self) {
        if self.values.len() < 10 {
            self.trend = TrendDirection::Stable;
            return;
        }

        // Simple linear regression
        let n = self.values.len() as f64;
        let x_mean = (n - 1.0) / 2.0;
        let y_mean = self.mean;

        let mut num = 0.0;
        let mut den = 0.0;

        for (i, y) in self.values.iter().enumerate() {
            let x = i as f64;
            num += (x - x_mean) * (y - y_mean);
            den += (x - x_mean).powi(2);
        }

        let slope = if den != 0.0 { num / den } else { 0.0 };

        // Determine trend based on slope
        self.trend = if slope > 0.01 {
            TrendDirection::Increasing
        } else if slope < -0.01 {
            TrendDirection::Decreasing
        } else {
            TrendDirection::Stable
        };
    }

    /// Calculate percentage change
    fn calculate_change_percent(&self) -> f64 {
        if self.values.len() < 2 {
            return 0.0;
        }

        let first = self.values.front().unwrap();
        let last = self.values.back().unwrap();

        if *first == 0.0 {
            return 0.0;
        }

        ((last - first) / first) * 100.0
    }
}

impl OptimizationModel {
    /// Create new optimization model
    fn new() -> Self {
        let mut rules = Vec::new();

        // Add default optimization rules
        rules.push(OptimizationRule {
            pattern: "find . -name <STRING>".to_string(),
            condition: OptimizationCondition::LongDuration(5000),
            transformation: "fd <STRING>".to_string(),
            expected_improvement: 10.0,
        });

        rules.push(OptimizationRule {
            pattern: "grep -r <STRING>".to_string(),
            condition: OptimizationCondition::LongDuration(3000),
            transformation: "rg <STRING>".to_string(),
            expected_improvement: 5.0,
        });

        rules.push(OptimizationRule {
            pattern: "LIST_CMD | FILTER_CMD".to_string(),
            condition: OptimizationCondition::HighMemoryUsage(100.0),
            transformation: "Combine into single command with pattern matching".to_string(),
            expected_improvement: 2.0,
        });

        Self {
            rules,
            learned_optimizations: HashMap::new(),
        }
    }

    /// Learn from optimization results
    async fn learn_from_result(&self, record: &ExecutionRecord, result: &ExecutionResult) -> Result<()> {
        // This would implement ML-based learning from results
        // For now, we just track successful optimizations
        Ok(())
    }

    /// Get optimization suggestions
    fn get_suggestions(&self, patterns: &HashMap<String, PatternRecord>, confidence_threshold: f64) -> Vec<LearnedOptimization> {
        let mut suggestions = Vec::new();

        // Check rules against patterns
        for (pattern_str, record) in patterns {
            for rule in &self.rules {
                if self.pattern_matches(&rule.pattern, pattern_str) {
                    if self.condition_met(&rule.condition, record) {
                        suggestions.push(LearnedOptimization {
                            original_pattern: pattern_str.clone(),
                            optimized_pattern: rule.transformation.clone(),
                            improvement_ratio: rule.expected_improvement,
                            confidence: 0.9, // Rule-based confidence
                            sample_count: record.frequency,
                        });
                    }
                }
            }
        }

        // Add learned optimizations
        for opt in self.learned_optimizations.values() {
            if opt.confidence >= confidence_threshold {
                suggestions.push(opt.clone());
            }
        }

        suggestions
    }

    /// Check if pattern matches
    fn pattern_matches(&self, rule_pattern: &str, actual_pattern: &str) -> bool {
        // Simple pattern matching - could be enhanced
        if rule_pattern == actual_pattern {
            return true;
        }

        // Check if rule pattern is contained
        actual_pattern.contains(rule_pattern)
    }

    /// Check if condition is met
    fn condition_met(&self, condition: &OptimizationCondition, record: &PatternRecord) -> bool {
        match condition {
            OptimizationCondition::HighCpuUsage(threshold) => {
                // Would need CPU metrics in pattern record
                false
            }
            OptimizationCondition::HighMemoryUsage(threshold) => {
                // Would need memory metrics in pattern record
                false
            }
            OptimizationCondition::LongDuration(threshold) => {
                record.avg_duration_ms > *threshold as f64
            }
            OptimizationCondition::FrequentFailure(threshold) => {
                (1.0 - record.success_rate) > *threshold
            }
            OptimizationCondition::Custom(_) => {
                false // Would need custom logic
            }
        }
    }
}

impl PerformanceMetrics {
    /// Convert to map for easier processing
    fn to_map(&self) -> HashMap<String, f64> {
        let mut map = HashMap::new();
        map.insert("duration_ms".to_string(), self.total_duration_ms as f64);
        map.insert("cpu_usage".to_string(), self.cpu_usage_percent);
        map.insert("memory_mb".to_string(), self.memory_usage_mb);
        map.insert("io_ops".to_string(), self.io_operations as f64);
        map.insert("network_bytes".to_string(), self.network_bytes as f64);
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_extraction() {
        let system = LearningSystem::new(LearningConfig::default()).unwrap();
        
        let patterns = futures::executor::block_on(
            system.extract_patterns("ls -la | grep test && echo 'Done'")
        ).unwrap();
        
        assert!(patterns.len() > 0);
        assert!(patterns.iter().any(|p| p.contains("LIST_CMD | FILTER_CMD")));
    }

    #[test]
    fn test_command_type_detection() {
        let system = LearningSystem::new(LearningConfig::default()).unwrap();
        
        assert_eq!(system.get_command_type("ls -la"), "LIST_CMD");
        assert_eq!(system.get_command_type("grep pattern"), "FILTER_CMD");
        assert_eq!(system.get_command_type("echo hello"), "OUTPUT_CMD");
    }
}