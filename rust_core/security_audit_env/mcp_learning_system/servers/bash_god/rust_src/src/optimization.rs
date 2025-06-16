use anyhow::{Result, anyhow};
use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use regex::Regex;
use once_cell::sync::Lazy;

use crate::memory::{MemoryPool, OptimizationHint, CommandPattern};
use crate::system_state::SystemContext;

static OPTIMIZATION_PATTERNS: Lazy<Vec<OptimizationPattern>> = Lazy::new(|| {
    vec![
        // Pipeline optimizations
        OptimizationPattern {
            name: "cat_grep_to_grep".to_string(),
            pattern: Regex::new(r"cat\s+(\S+)\s*\|\s*grep").unwrap(),
            replacement: "grep {} $1".to_string(),
            improvement: 1.5,
            description: "grep can read files directly".to_string(),
        },
        OptimizationPattern {
            name: "multiple_greps".to_string(),
            pattern: Regex::new(r"grep\s+(\S+).*\|\s*grep\s+(\S+)").unwrap(),
            replacement: "grep -E '$1.*$2'".to_string(),
            improvement: 1.8,
            description: "Combine multiple greps with regex".to_string(),
        },
        OptimizationPattern {
            name: "find_exec_to_xargs".to_string(),
            pattern: Regex::new(r"find\s+(.*?)\s+-exec\s+(\S+)\s+\{\}\s*\\;").unwrap(),
            replacement: "find $1 -print0 | xargs -0 $2".to_string(),
            improvement: 3.0,
            description: "xargs is more efficient than -exec".to_string(),
        },
        
        // Sort optimizations
        OptimizationPattern {
            name: "sort_uniq_to_sort_u".to_string(),
            pattern: Regex::new(r"sort\s*(.*?)\s*\|\s*uniq").unwrap(),
            replacement: "sort -u $1".to_string(),
            improvement: 1.3,
            description: "sort -u combines sort and uniq".to_string(),
        },
        
        // AWK optimizations
        OptimizationPattern {
            name: "grep_awk_to_awk".to_string(),
            pattern: Regex::new(r"grep\s+'([^']+)'\s*\|\s*awk").unwrap(),
            replacement: "awk '/$1/ {}'".to_string(),
            improvement: 1.4,
            description: "awk can filter and process in one pass".to_string(),
        },
        
        // Loop optimizations
        OptimizationPattern {
            name: "for_loop_to_parallel".to_string(),
            pattern: Regex::new(r"for\s+\w+\s+in\s+.*;\s*do\s+(.*?);\s*done").unwrap(),
            replacement: "parallel -j+0 '$1' ::: $list".to_string(),
            improvement: 4.0,
            description: "GNU parallel for CPU-bound tasks".to_string(),
        },
    ]
});

#[derive(Clone, Debug)]
pub struct OptimizationPattern {
    pub name: String,
    pub pattern: Regex,
    pub replacement: String,
    pub improvement: f64,
    pub description: String,
}

pub struct PatternOptimizer {
    memory_pool: Arc<MemoryPool>,
    custom_patterns: Arc<RwLock<Vec<OptimizationPattern>>>,
    performance_history: Arc<RwLock<HashMap<String, PerformanceMetrics>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub command_hash: String,
    pub execution_count: u64,
    pub average_duration_ms: f64,
    pub cpu_efficiency: f64,
    pub memory_efficiency: f64,
    pub improvement_suggestions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OptimizationRequest {
    pub command: String,
    pub context: SystemContext,
    pub performance_priority: PerformancePriority,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum PerformancePriority {
    Speed,
    Memory,
    CpuEfficiency,
    Balanced,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OptimizationResult {
    pub original_command: String,
    pub optimized_command: String,
    pub improvements: Vec<Improvement>,
    pub estimated_speedup: f64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Improvement {
    pub rule_name: String,
    pub description: String,
    pub impact: f64,
}

impl PatternOptimizer {
    pub fn new(memory_pool: Arc<MemoryPool>) -> Self {
        Self {
            memory_pool,
            custom_patterns: Arc::new(RwLock::new(vec![])),
            performance_history: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub async fn optimize(&self, command: String) -> Result<String> {
        let mut optimized = command.clone();
        let mut total_improvement = 1.0;
        
        // Apply built-in patterns
        for pattern in OPTIMIZATION_PATTERNS.iter() {
            if let Some(result) = self.apply_pattern(&optimized, pattern) {
                optimized = result;
                total_improvement *= pattern.improvement;
            }
        }
        
        // Apply custom patterns
        let custom = self.custom_patterns.read();
        for pattern in custom.iter() {
            if let Some(result) = self.apply_pattern(&optimized, pattern) {
                optimized = result;
                total_improvement *= pattern.improvement;
            }
        }
        
        // Apply context-specific optimizations
        if let Some(hints) = self.memory_pool.find_optimization_hints(&command).first() {
            if hints.improvement_factor > total_improvement {
                optimized = hints.optimized_pattern.clone();
            }
        }
        
        Ok(optimized)
    }
    
    pub async fn optimize_with_context(&self, request: OptimizationRequest) -> Result<OptimizationResult> {
        let mut optimized = request.command.clone();
        let mut improvements = vec![];
        let mut warnings = vec![];
        let mut total_speedup = 1.0;
        
        // Context-aware optimizations
        match request.performance_priority {
            PerformancePriority::Speed => {
                optimized = self.optimize_for_speed(optimized, &request.context)?;
            }
            PerformancePriority::Memory => {
                optimized = self.optimize_for_memory(optimized, &request.context)?;
            }
            PerformancePriority::CpuEfficiency => {
                optimized = self.optimize_for_cpu(optimized, &request.context)?;
            }
            PerformancePriority::Balanced => {
                optimized = self.optimize_balanced(optimized, &request.context)?;
            }
        }
        
        // Apply pattern-based optimizations
        for pattern in OPTIMIZATION_PATTERNS.iter() {
            if pattern.pattern.is_match(&optimized) {
                if let Some(result) = self.apply_pattern(&optimized, pattern) {
                    improvements.push(Improvement {
                        rule_name: pattern.name.clone(),
                        description: pattern.description.clone(),
                        impact: pattern.improvement,
                    });
                    optimized = result;
                    total_speedup *= pattern.improvement;
                }
            }
        }
        
        // Add warnings for potentially risky optimizations
        if optimized.contains("parallel") && !request.command.contains("parallel") {
            warnings.push("Added parallel processing - ensure commands are independent".to_string());
        }
        
        if optimized.contains("xargs") && !request.command.contains("xargs") {
            warnings.push("Using xargs - be careful with special characters in filenames".to_string());
        }
        
        Ok(OptimizationResult {
            original_command: request.command,
            optimized_command: optimized,
            improvements,
            estimated_speedup: total_speedup,
            warnings,
        })
    }
    
    pub fn learn(&self, pattern: LearningPattern) -> Result<()> {
        let hint = OptimizationHint {
            hint_id: format!("learned_{}", chrono::Utc::now().timestamp_millis()),
            original_pattern: pattern.original,
            optimized_pattern: pattern.optimized,
            improvement_factor: pattern.measured_improvement,
            conditions: pattern.conditions,
            size_bytes: 0,
        };
        
        self.memory_pool.store_optimization_hint(hint)?;
        
        // Add to custom patterns if significant improvement
        if pattern.measured_improvement > 1.2 {
            let mut custom = self.custom_patterns.write();
            custom.push(OptimizationPattern {
                name: format!("custom_{}", custom.len()),
                pattern: Regex::new(&regex::escape(&pattern.original))?,
                replacement: pattern.optimized.clone(),
                improvement: pattern.measured_improvement,
                description: "Learned from execution".to_string(),
            });
        }
        
        Ok(())
    }
    
    fn apply_pattern(&self, command: &str, pattern: &OptimizationPattern) -> Option<String> {
        if pattern.pattern.is_match(command) {
            let result = pattern.pattern.replace(command, &pattern.replacement);
            Some(result.to_string())
        } else {
            None
        }
    }
    
    fn optimize_for_speed(&self, command: String, context: &SystemContext) -> Result<String> {
        let mut optimized = command;
        
        // Use parallel processing if multiple cores available
        if context.cpu_cores > 2 {
            // Convert sequential operations to parallel
            if optimized.contains("for ") && optimized.contains("done") {
                if !optimized.contains("parallel") {
                    // Extract loop body and convert to parallel
                    optimized = self.parallelize_loop(&optimized)?;
                }
            }
            
            // Use parallel compression/decompression
            if optimized.contains("gzip") && !optimized.contains("pigz") {
                optimized = optimized.replace("gzip", "pigz");
            }
            if optimized.contains("bzip2") && !optimized.contains("pbzip2") {
                optimized = optimized.replace("bzip2", "pbzip2");
            }
        }
        
        // Use faster alternatives
        if optimized.contains("grep") && !optimized.contains("rg") {
            if which::which("rg").is_ok() {
                optimized = optimized.replace("grep", "rg");
            }
        }
        
        if optimized.contains("find") && !optimized.contains("fd") {
            if which::which("fd").is_ok() {
                optimized = self.convert_find_to_fd(&optimized)?;
            }
        }
        
        Ok(optimized)
    }
    
    fn optimize_for_memory(&self, command: String, context: &SystemContext) -> Result<String> {
        let mut optimized = command;
        
        // Add memory limits to sort
        if optimized.contains("sort") && !optimized.contains("-S") {
            let memory_limit = context.available_memory_mb / 4;
            optimized = optimized.replace("sort", &format!("sort -S {}M", memory_limit));
        }
        
        // Use streaming operations
        if optimized.contains("cat") && optimized.contains("|") {
            optimized = self.optimize_cat_pipeline(&optimized)?;
        }
        
        // Limit parallel jobs based on available memory
        if optimized.contains("parallel") {
            let max_jobs = (context.available_memory_mb / 512).max(1);
            optimized = optimized.replace("parallel", &format!("parallel -j{}", max_jobs));
        }
        
        Ok(optimized)
    }
    
    fn optimize_for_cpu(&self, command: String, context: &SystemContext) -> Result<String> {
        let mut optimized = command;
        
        // Set nice values for background tasks
        if !optimized.starts_with("nice") && self.is_background_task(&optimized) {
            optimized = format!("nice -n 10 {}", optimized);
        }
        
        // Use CPU-efficient compression
        if optimized.contains("xz") {
            let threads = context.cpu_cores / 2;
            optimized = optimized.replace("xz", &format!("xz -T{}", threads));
        }
        
        // Optimize grep for large files
        if optimized.contains("grep") && optimized.contains("-r") {
            optimized = optimized.replace("grep -r", "grep -r --binary-files=without-match");
        }
        
        Ok(optimized)
    }
    
    fn optimize_balanced(&self, command: String, context: &SystemContext) -> Result<String> {
        let mut optimized = command;
        
        // Apply moderate optimizations from each category
        if context.cpu_cores > 4 && optimized.contains("xargs") && !optimized.contains("-P") {
            optimized = optimized.replace("xargs", &format!("xargs -P{}", context.cpu_cores / 2));
        }
        
        if context.available_memory_mb < 2048 && optimized.contains("sort") {
            optimized = optimized.replace("sort", "sort -S 512M");
        }
        
        // Use efficient tools if available
        if which::which("moreutils").is_ok() {
            if optimized.contains("tee") && optimized.contains(">(") {
                optimized = optimized.replace("tee", "pee");
            }
        }
        
        Ok(optimized)
    }
    
    fn parallelize_loop(&self, command: &str) -> Result<String> {
        // Simple for loop parallelization
        let for_pattern = Regex::new(r"for\s+(\w+)\s+in\s+(.*?);\s*do\s+(.*?);\s*done")?;
        
        if let Some(captures) = for_pattern.captures(command) {
            let var = &captures[1];
            let list = &captures[2];
            let body = &captures[3];
            
            return Ok(format!(
                "echo {} | tr ' ' '\\n' | parallel -j+0 '{}'",
                list, 
                body.replace(&format!("${}", var), "{}")
            ));
        }
        
        Ok(command.to_string())
    }
    
    fn convert_find_to_fd(&self, command: &str) -> Result<String> {
        // Convert common find patterns to fd
        let mut result = command.to_string();
        
        result = result.replace("find . -name", "fd");
        result = result.replace("find . -type f -name", "fd -t f");
        result = result.replace("find . -type d -name", "fd -t d");
        
        Ok(result)
    }
    
    fn optimize_cat_pipeline(&self, command: &str) -> Result<String> {
        // Remove unnecessary cat commands
        let cat_pattern = Regex::new(r"cat\s+(\S+)\s*\|\s*(\w+)")?;
        
        if let Some(captures) = cat_pattern.captures(command) {
            let file = &captures[1];
            let next_cmd = &captures[2];
            
            // Most commands can read files directly
            return Ok(command.replace(
                &format!("cat {} | {}", file, next_cmd),
                &format!("{} {}", next_cmd, file)
            ));
        }
        
        Ok(command.to_string())
    }
    
    fn is_background_task(&self, command: &str) -> bool {
        let background_indicators = vec![
            "backup", "compress", "archive", "sync", "rsync",
            "tar", "zip", "find", "updatedb"
        ];
        
        let cmd_lower = command.to_lowercase();
        background_indicators.iter().any(|indicator| cmd_lower.contains(indicator))
    }
    
    pub fn record_performance(&self, command: String, metrics: PerformanceMetrics) -> Result<()> {
        let mut history = self.performance_history.write();
        history.insert(command, metrics);
        Ok(())
    }
    
    pub fn suggest_improvements(&self, command: &str) -> Vec<String> {
        let mut suggestions = vec![];
        
        // Check performance history
        if let Some(metrics) = self.performance_history.read().get(command) {
            suggestions.extend(metrics.improvement_suggestions.clone());
        }
        
        // Check for common inefficiencies
        if command.contains("cat") && command.contains("|") && command.contains("grep") {
            suggestions.push("Consider using grep directly on the file".to_string());
        }
        
        if command.contains("for") && command.contains("in") && command.contains("do") {
            suggestions.push("Consider using GNU parallel for better performance".to_string());
        }
        
        if command.contains("find") && command.contains("-exec") && command.contains("{}") {
            suggestions.push("Consider using find with xargs for better performance".to_string());
        }
        
        suggestions
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LearningPattern {
    pub original: String,
    pub optimized: String,
    pub measured_improvement: f64,
    pub conditions: Vec<String>,
}