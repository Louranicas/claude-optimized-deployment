use anyhow::{Result, anyhow};
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use crate::memory::{MemoryPool, CommandPattern};
use crate::system_state::SystemContext;

static COMMAND_TEMPLATES: Lazy<HashMap<&'static str, CommandTemplate>> = Lazy::new(|| {
    let mut templates = HashMap::new();
    
    // File operations
    templates.insert("find_large_files", CommandTemplate {
        pattern: "find {path} -type f -size +{size}M -printf \"%s %p\\n\" 2>/dev/null | sort -nr | head -{limit}",
        variables: vec!["path", "size", "limit"],
        safety_level: SafetyLevel::Safe,
        optimization_hints: vec![
            "Use -printf for efficiency",
            "Redirect errors to avoid clutter",
            "Combine with sort for immediate results"
        ],
    });
    
    templates.insert("find_old_files", CommandTemplate {
        pattern: "find {path} -type f -mtime +{days} -exec ls -lh {} \\; | sort -k5 -hr",
        variables: vec!["path", "days"],
        safety_level: SafetyLevel::Safe,
        optimization_hints: vec![
            "Use -mtime for modification time",
            "Human-readable sizes with ls -lh"
        ],
    });
    
    // Process management
    templates.insert("find_process_by_port", CommandTemplate {
        pattern: "lsof -i :{port} | grep LISTEN || netstat -tlnp 2>/dev/null | grep :{port}",
        variables: vec!["port"],
        safety_level: SafetyLevel::Safe,
        optimization_hints: vec![
            "Try lsof first, fallback to netstat",
            "Filter for LISTEN state only"
        ],
    });
    
    templates.insert("kill_process_by_name", CommandTemplate {
        pattern: "pkill -f '{pattern}' || killall -v '{pattern}'",
        variables: vec!["pattern"],
        safety_level: SafetyLevel::Destructive,
        optimization_hints: vec![
            "Use pkill for pattern matching",
            "Fallback to killall if needed"
        ],
    });
    
    // Docker operations
    templates.insert("docker_cleanup", CommandTemplate {
        pattern: "docker system prune -a --volumes -f --filter \"until={hours}h\"",
        variables: vec!["hours"],
        safety_level: SafetyLevel::Destructive,
        optimization_hints: vec![
            "Use --filter for time-based cleanup",
            "Include volumes with --volumes flag"
        ],
    });
    
    templates.insert("docker_stats", CommandTemplate {
        pattern: "docker stats --no-stream --format \"table {{.Container}}\\t{{.CPUPerc}}\\t{{.MemUsage}}\\t{{.NetIO}}\"",
        variables: vec![],
        safety_level: SafetyLevel::Safe,
        optimization_hints: vec![
            "Use --no-stream for one-time output",
            "Custom format for readability"
        ],
    });
    
    // System monitoring
    templates.insert("disk_usage", CommandTemplate {
        pattern: "df -h | awk '$5+0 > {threshold} {print $0}' | sort -k5 -nr",
        variables: vec!["threshold"],
        safety_level: SafetyLevel::Safe,
        optimization_hints: vec![
            "Filter by usage percentage",
            "Sort by usage descending"
        ],
    });
    
    templates.insert("memory_usage", CommandTemplate {
        pattern: "ps aux --sort=-%mem | head -{limit} | awk '{printf \"%-10s %-8s %-8s %s\\n\", $1, $3, $4, $11}'",
        variables: vec!["limit"],
        safety_level: SafetyLevel::Safe,
        optimization_hints: vec![
            "Sort by memory usage",
            "Format output for clarity"
        ],
    });
    
    // Network operations
    templates.insert("network_connections", CommandTemplate {
        pattern: "ss -tanp | grep -E '(ESTAB|LISTEN)' | awk '{print $4, $5, $6}' | sort | uniq -c | sort -nr",
        variables: vec![],
        safety_level: SafetyLevel::Safe,
        optimization_hints: vec![
            "Use ss instead of netstat",
            "Count unique connections"
        ],
    });
    
    // Log analysis
    templates.insert("analyze_logs", CommandTemplate {
        pattern: "grep -E '{pattern}' {logfile} | tail -{lines} | awk '{print $1, $2, $NF}'",
        variables: vec!["pattern", "logfile", "lines"],
        safety_level: SafetyLevel::Safe,
        optimization_hints: vec![
            "Use extended regex",
            "Extract relevant fields with awk"
        ],
    });
    
    templates
});

#[derive(Clone, Debug)]
pub struct CommandTemplate {
    pub pattern: &'static str,
    pub variables: Vec<&'static str>,
    pub safety_level: SafetyLevel,
    pub optimization_hints: Vec<&'static str>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SafetyLevel {
    Safe,
    Moderate,
    Destructive,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommandRequest {
    pub task: String,
    pub context: HashMap<String, String>,
    pub constraints: Vec<String>,
    pub dry_run: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommandResponse {
    pub command: String,
    pub explanation: String,
    pub safety_level: String,
    pub alternatives: Vec<String>,
    pub warnings: Vec<String>,
}

pub struct CommandEngine {
    memory_pool: Arc<MemoryPool>,
    pattern_matcher: Arc<RwLock<PatternMatcher>>,
    command_builder: Arc<CommandBuilder>,
}

pub struct PatternMatcher {
    task_patterns: HashMap<String, Vec<String>>,
    learned_mappings: HashMap<String, String>,
}

pub struct CommandBuilder {
    variable_resolver: VariableResolver,
    safety_checker: SafetyChecker,
}

pub struct VariableResolver {
    default_values: HashMap<String, String>,
}

pub struct SafetyChecker {
    dangerous_patterns: Vec<Regex>,
    safe_guards: HashMap<String, String>,
}

impl CommandEngine {
    pub fn new(memory_pool: Arc<MemoryPool>) -> Self {
        Self {
            memory_pool,
            pattern_matcher: Arc::new(RwLock::new(PatternMatcher::new())),
            command_builder: Arc::new(CommandBuilder::new()),
        }
    }
    
    pub async fn generate(&self, request: &CommandRequest, context: &SystemContext) -> Result<CommandResponse> {
        // Match task to template
        let template_name = self.match_task_to_template(&request.task)?;
        let template = COMMAND_TEMPLATES.get(template_name.as_str())
            .ok_or_else(|| anyhow!("No template found for task"))?;
        
        // Check if we have learned patterns
        if let Some(pattern) = self.get_learned_pattern(&request.task) {
            return self.build_from_pattern(pattern, request, context).await;
        }
        
        // Build command from template
        let command = self.command_builder.build(template, &request.context)?;
        
        // Apply optimizations based on context
        let optimized = self.optimize_for_context(command, context)?;
        
        // Generate alternatives
        let alternatives = self.generate_alternatives(&request.task, template)?;
        
        // Safety check
        let warnings = self.command_builder.safety_checker.check(&optimized)?;
        
        Ok(CommandResponse {
            command: if request.dry_run {
                format!("echo 'DRY RUN: {}'", optimized)
            } else {
                optimized
            },
            explanation: self.generate_explanation(template, &request.task),
            safety_level: format!("{:?}", template.safety_level),
            alternatives,
            warnings,
        })
    }
    
    fn match_task_to_template(&self, task: &str) -> Result<String> {
        let task_lower = task.to_lowercase();
        
        // Direct matches
        if task_lower.contains("large files") || task_lower.contains("big files") {
            return Ok("find_large_files".to_string());
        }
        if task_lower.contains("old files") || task_lower.contains("ancient files") {
            return Ok("find_old_files".to_string());
        }
        if task_lower.contains("process") && task_lower.contains("port") {
            return Ok("find_process_by_port".to_string());
        }
        if task_lower.contains("kill") && task_lower.contains("process") {
            return Ok("kill_process_by_name".to_string());
        }
        if task_lower.contains("docker") && task_lower.contains("clean") {
            return Ok("docker_cleanup".to_string());
        }
        if task_lower.contains("docker") && task_lower.contains("stats") {
            return Ok("docker_stats".to_string());
        }
        if task_lower.contains("disk") && (task_lower.contains("usage") || task_lower.contains("space")) {
            return Ok("disk_usage".to_string());
        }
        if task_lower.contains("memory") && task_lower.contains("usage") {
            return Ok("memory_usage".to_string());
        }
        if task_lower.contains("network") && task_lower.contains("connection") {
            return Ok("network_connections".to_string());
        }
        if task_lower.contains("log") && (task_lower.contains("analyze") || task_lower.contains("search")) {
            return Ok("analyze_logs".to_string());
        }
        
        // Check learned mappings
        let matcher = self.pattern_matcher.read();
        if let Some(template) = matcher.learned_mappings.get(task) {
            return Ok(template.clone());
        }
        
        Err(anyhow!("No matching template found for task: {}", task))
    }
    
    fn get_learned_pattern(&self, task: &str) -> Option<CommandPattern> {
        self.memory_pool.get_command_pattern(task)
    }
    
    async fn build_from_pattern(&self, pattern: CommandPattern, request: &CommandRequest, context: &SystemContext) -> Result<CommandResponse> {
        let command = self.apply_context_to_pattern(&pattern.pattern, &request.context)?;
        
        Ok(CommandResponse {
            command: if request.dry_run {
                format!("echo 'DRY RUN: {}'", command)
            } else {
                command
            },
            explanation: format!("Using learned pattern with {}% success rate", pattern.success_rate * 100.0),
            safety_level: "Learned".to_string(),
            alternatives: pattern.optimizations.clone(),
            warnings: vec![],
        })
    }
    
    fn apply_context_to_pattern(&self, pattern: &str, context: &HashMap<String, String>) -> Result<String> {
        let mut result = pattern.to_string();
        for (key, value) in context {
            result = result.replace(&format!("{{{}}}", key), value);
        }
        Ok(result)
    }
    
    fn optimize_for_context(&self, command: String, context: &SystemContext) -> Result<String> {
        let mut optimized = command;
        
        // Apply system-specific optimizations
        if context.cpu_cores > 4 {
            // Use parallel processing where possible
            if optimized.contains("find") && !optimized.contains("parallel") {
                optimized = format!("{} | parallel -j{} --", optimized, context.cpu_cores / 2);
            }
        }
        
        if context.available_memory_mb < 1024 {
            // Add memory-conscious flags
            if optimized.contains("sort") && !optimized.contains("-S") {
                optimized = optimized.replace("sort", "sort -S 256M");
            }
        }
        
        Ok(optimized)
    }
    
    fn generate_alternatives(&self, task: &str, template: &CommandTemplate) -> Result<Vec<String>> {
        let mut alternatives = vec![];
        
        // Add template optimization hints as alternatives
        for hint in &template.optimization_hints {
            alternatives.push(format!("Tip: {}", hint));
        }
        
        // Add safety alternatives for destructive operations
        if template.safety_level == SafetyLevel::Destructive {
            alternatives.push("Consider running with --dry-run first".to_string());
            alternatives.push("Create a backup before proceeding".to_string());
        }
        
        Ok(alternatives)
    }
    
    fn generate_explanation(&self, template: &CommandTemplate, task: &str) -> String {
        format!(
            "Generated command for '{}' using {} template. Safety level: {:?}",
            task, 
            template.pattern.split_whitespace().next().unwrap_or("custom"),
            template.safety_level
        )
    }
    
    pub fn learn_from_execution(&self, task: String, command: String, success: bool, duration_ms: u64) -> Result<()> {
        let mut pattern = CommandPattern {
            pattern: command.clone(),
            frequency: 1,
            success_rate: if success { 1.0 } else { 0.0 },
            average_duration_ms: duration_ms,
            contexts: vec![task.clone()],
            optimizations: vec![],
            size_bytes: 0,
        };
        
        pattern.calculate_size();
        
        if let Some(existing) = self.memory_pool.get_command_pattern(&task) {
            // Update existing pattern
            self.memory_pool.update_command_pattern(&task, |p| {
                p.frequency += 1;
                p.success_rate = (p.success_rate * (p.frequency - 1) as f64 + if success { 1.0 } else { 0.0 }) / p.frequency as f64;
                p.average_duration_ms = (p.average_duration_ms * (p.frequency - 1) + duration_ms) / p.frequency;
                p.calculate_size();
            })?;
        } else {
            // Store new pattern
            self.memory_pool.store_command_pattern(task.clone(), pattern)?;
            
            // Update pattern matcher
            let mut matcher = self.pattern_matcher.write();
            matcher.learned_mappings.insert(task, command);
        }
        
        Ok(())
    }
}

impl PatternMatcher {
    fn new() -> Self {
        Self {
            task_patterns: HashMap::new(),
            learned_mappings: HashMap::new(),
        }
    }
}

impl CommandBuilder {
    fn new() -> Self {
        Self {
            variable_resolver: VariableResolver::new(),
            safety_checker: SafetyChecker::new(),
        }
    }
    
    fn build(&self, template: &CommandTemplate, context: &HashMap<String, String>) -> Result<String> {
        let mut command = template.pattern.to_string();
        
        // Resolve variables
        for var in &template.variables {
            let value = context.get(*var)
                .or_else(|| self.variable_resolver.get_default(var))
                .ok_or_else(|| anyhow!("Missing required variable: {}", var))?;
            
            command = command.replace(&format!("{{{}}}", var), value);
        }
        
        Ok(command)
    }
}

impl VariableResolver {
    fn new() -> Self {
        let mut defaults = HashMap::new();
        defaults.insert("path".to_string(), ".".to_string());
        defaults.insert("size".to_string(), "100".to_string());
        defaults.insert("limit".to_string(), "20".to_string());
        defaults.insert("days".to_string(), "30".to_string());
        defaults.insert("hours".to_string(), "24".to_string());
        defaults.insert("threshold".to_string(), "80".to_string());
        defaults.insert("lines".to_string(), "100".to_string());
        
        Self { default_values: defaults }
    }
    
    fn get_default(&self, var: &str) -> Option<&String> {
        self.default_values.get(var)
    }
}

impl SafetyChecker {
    fn new() -> Self {
        let dangerous_patterns = vec![
            Regex::new(r"rm\s+-rf\s+/").unwrap(),
            Regex::new(r"dd\s+.*of=/dev/[sh]d").unwrap(),
            Regex::new(r"mkfs\.").unwrap(),
            Regex::new(r"chmod\s+777\s+/").unwrap(),
            Regex::new(r":(){ :|:& };:").unwrap(), // Fork bomb
        ];
        
        let mut safe_guards = HashMap::new();
        safe_guards.insert("rm".to_string(), "Consider using trash-cli instead".to_string());
        safe_guards.insert("dd".to_string(), "Always double-check device paths".to_string());
        safe_guards.insert("mkfs".to_string(), "This will destroy all data on the device".to_string());
        
        Self { dangerous_patterns, safe_guards }
    }
    
    fn check(&self, command: &str) -> Result<Vec<String>> {
        let mut warnings = vec![];
        
        for pattern in &self.dangerous_patterns {
            if pattern.is_match(command) {
                warnings.push(format!("DANGEROUS: Command matches pattern '{}'", pattern.as_str()));
            }
        }
        
        for (cmd, warning) in &self.safe_guards {
            if command.contains(cmd) {
                warnings.push(warning.clone());
            }
        }
        
        Ok(warnings)
    }
}