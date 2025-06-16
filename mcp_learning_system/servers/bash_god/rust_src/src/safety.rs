use anyhow::{Result, anyhow};
use regex::Regex;
use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;

use crate::memory::{MemoryPool, SafetyRule, RiskLevel};

#[derive(Debug, Serialize, Deserialize)]
pub struct SafetyValidationRequest {
    pub command: String,
    pub context: HashMap<String, String>,
    pub user: String,
    pub working_directory: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SafetyValidationResult {
    pub is_safe: bool,
    pub risk_level: String,
    pub warnings: Vec<String>,
    pub mitigations: Vec<String>,
    pub suggested_command: Option<String>,
}

pub struct SafetyValidator {
    memory_pool: Arc<MemoryPool>,
    builtin_rules: Arc<Vec<SafetyRule>>,
    path_validator: Arc<PathValidator>,
    permission_checker: Arc<PermissionChecker>,
    command_sanitizer: Arc<CommandSanitizer>,
}

pub struct PathValidator {
    protected_paths: Vec<PathBuf>,
    allowed_paths: Vec<PathBuf>,
}

pub struct PermissionChecker {
    dangerous_permissions: Vec<String>,
    safe_operations: HashMap<String, Vec<String>>,
}

pub struct CommandSanitizer {
    dangerous_patterns: Vec<Regex>,
    escape_sequences: Vec<Regex>,
    safe_replacements: HashMap<String, String>,
}

impl SafetyValidator {
    pub fn new(memory_pool: Arc<MemoryPool>) -> Result<Self> {
        let builtin_rules = Self::create_builtin_rules();
        
        Ok(Self {
            memory_pool,
            builtin_rules: Arc::new(builtin_rules),
            path_validator: Arc::new(PathValidator::new()),
            permission_checker: Arc::new(PermissionChecker::new()),
            command_sanitizer: Arc::new(CommandSanitizer::new()),
        })
    }
    
    pub async fn validate(&self, command: &str) -> Result<SafetyValidationResult> {
        let mut warnings = vec![];
        let mut mitigations = vec![];
        let mut risk_level = RiskLevel::Low;
        
        // Check against builtin rules
        for rule in self.builtin_rules.iter() {
            if self.matches_rule(command, rule) {
                warnings.push(format!("Matches safety rule: {}", rule.rule_id));
                mitigations.extend(rule.mitigations.clone());
                risk_level = self.max_risk_level(risk_level, rule.risk_level.clone());
            }
        }
        
        // Check against learned rules
        for rule in self.memory_pool.get_safety_rules() {
            if self.matches_rule(command, &rule) {
                warnings.push(format!("Matches learned rule: {}", rule.rule_id));
                mitigations.extend(rule.mitigations);
                risk_level = self.max_risk_level(risk_level, rule.risk_level);
            }
        }
        
        // Validate paths
        let path_warnings = self.path_validator.validate(command)?;
        warnings.extend(path_warnings);
        
        // Check permissions
        let perm_warnings = self.permission_checker.check(command)?;
        warnings.extend(perm_warnings);
        
        // Check for dangerous patterns
        let (sanitized, san_warnings) = self.command_sanitizer.sanitize(command)?;
        warnings.extend(san_warnings);
        
        let is_safe = matches!(risk_level, RiskLevel::Low | RiskLevel::Medium) && warnings.is_empty();
        
        Ok(SafetyValidationResult {
            is_safe,
            risk_level: format!("{:?}", risk_level),
            warnings,
            mitigations,
            suggested_command: if command != sanitized {
                Some(sanitized)
            } else {
                None
            },
        })
    }
    
    pub fn add_rule(&self, execution: &CommandExecution) -> Result<()> {
        if execution.exit_code != 0 || execution.had_errors {
            let rule = SafetyRule {
                rule_id: format!("learned_{}", chrono::Utc::now().timestamp()),
                pattern: self.extract_pattern(&execution.command),
                risk_level: if execution.was_destructive {
                    RiskLevel::High
                } else {
                    RiskLevel::Medium
                },
                mitigations: vec![
                    format!("Previous execution failed with: {}", execution.error_message),
                    "Consider alternative approach".to_string(),
                ],
                size_bytes: 0,
            };
            
            self.memory_pool.store_safety_rule(rule)?;
        }
        
        Ok(())
    }
    
    fn create_builtin_rules() -> Vec<SafetyRule> {
        vec![
            SafetyRule {
                rule_id: "rm_root".to_string(),
                pattern: r"rm\s+(-rf?|--force|--recursive)\s*/".to_string(),
                risk_level: RiskLevel::Critical,
                mitigations: vec![
                    "NEVER run rm -rf on root directory".to_string(),
                    "Use --preserve-root flag".to_string(),
                ],
                size_bytes: 0,
            },
            SafetyRule {
                rule_id: "dd_device".to_string(),
                pattern: r"dd\s+.*of=/dev/(sd|hd|nvme)".to_string(),
                risk_level: RiskLevel::Critical,
                mitigations: vec![
                    "Writing directly to block devices can destroy data".to_string(),
                    "Double-check device path".to_string(),
                    "Consider using conv=sync,noerror".to_string(),
                ],
                size_bytes: 0,
            },
            SafetyRule {
                rule_id: "fork_bomb".to_string(),
                pattern: r":\(\)\s*\{\s*:\|:&\s*\};?:?".to_string(),
                risk_level: RiskLevel::Critical,
                mitigations: vec![
                    "This is a fork bomb that will crash the system".to_string(),
                    "Do not execute under any circumstances".to_string(),
                ],
                size_bytes: 0,
            },
            SafetyRule {
                rule_id: "chmod_777".to_string(),
                pattern: r"chmod\s+777".to_string(),
                risk_level: RiskLevel::High,
                mitigations: vec![
                    "Setting 777 permissions is a security risk".to_string(),
                    "Use more restrictive permissions like 755 or 644".to_string(),
                ],
                size_bytes: 0,
            },
            SafetyRule {
                rule_id: "curl_pipe_sh".to_string(),
                pattern: r"curl.*\|\s*(sudo\s+)?sh".to_string(),
                risk_level: RiskLevel::High,
                mitigations: vec![
                    "Piping curl to shell is dangerous".to_string(),
                    "Download and inspect the script first".to_string(),
                ],
                size_bytes: 0,
            },
            SafetyRule {
                rule_id: "truncate_file".to_string(),
                pattern: r">\s*/[^>]+\.(log|conf|cfg|txt)".to_string(),
                risk_level: RiskLevel::Medium,
                mitigations: vec![
                    "This will truncate the file".to_string(),
                    "Consider backing up first".to_string(),
                ],
                size_bytes: 0,
            },
        ]
    }
    
    fn matches_rule(&self, command: &str, rule: &SafetyRule) -> bool {
        Regex::new(&rule.pattern)
            .map(|re| re.is_match(command))
            .unwrap_or(false)
    }
    
    fn max_risk_level(&self, a: RiskLevel, b: RiskLevel) -> RiskLevel {
        match (a, b) {
            (RiskLevel::Critical, _) | (_, RiskLevel::Critical) => RiskLevel::Critical,
            (RiskLevel::High, _) | (_, RiskLevel::High) => RiskLevel::High,
            (RiskLevel::Medium, _) | (_, RiskLevel::Medium) => RiskLevel::Medium,
            _ => RiskLevel::Low,
        }
    }
    
    fn extract_pattern(&self, command: &str) -> String {
        // Extract the command pattern for learning
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return String::new();
        }
        
        // Get base command and first few args
        let base = parts[0];
        let args: Vec<&str> = parts.iter()
            .skip(1)
            .take(2)
            .filter(|arg| arg.starts_with('-'))
            .copied()
            .collect();
        
        format!("{} {}", base, args.join(" "))
    }
}

impl PathValidator {
    fn new() -> Self {
        let protected_paths = vec![
            PathBuf::from("/"),
            PathBuf::from("/bin"),
            PathBuf::from("/boot"),
            PathBuf::from("/dev"),
            PathBuf::from("/etc"),
            PathBuf::from("/lib"),
            PathBuf::from("/lib64"),
            PathBuf::from("/proc"),
            PathBuf::from("/root"),
            PathBuf::from("/sbin"),
            PathBuf::from("/sys"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/usr/sbin"),
        ];
        
        let allowed_paths = vec![
            PathBuf::from("/tmp"),
            PathBuf::from("/var/tmp"),
            PathBuf::from("/home"),
        ];
        
        Self { protected_paths, allowed_paths }
    }
    
    fn validate(&self, command: &str) -> Result<Vec<String>> {
        let mut warnings = vec![];
        
        // Extract paths from command
        let paths = self.extract_paths(command);
        
        for path in paths {
            if self.is_protected(&path) && !self.is_read_only_operation(command) {
                warnings.push(format!("Operating on protected path: {}", path.display()));
            }
        }
        
        Ok(warnings)
    }
    
    fn extract_paths(&self, command: &str) -> Vec<PathBuf> {
        let mut paths = vec![];
        let parts: Vec<&str> = command.split_whitespace().collect();
        
        for part in parts {
            if part.starts_with('/') || part.starts_with("~/") {
                paths.push(PathBuf::from(part));
            }
        }
        
        paths
    }
    
    fn is_protected(&self, path: &Path) -> bool {
        for protected in &self.protected_paths {
            if path.starts_with(protected) {
                // Check if it's in allowed paths
                for allowed in &self.allowed_paths {
                    if path.starts_with(allowed) {
                        return false;
                    }
                }
                return true;
            }
        }
        false
    }
    
    fn is_read_only_operation(&self, command: &str) -> bool {
        let read_only_commands = vec!["ls", "cat", "head", "tail", "grep", "find", "stat", "file", "less", "more"];
        let parts: Vec<&str> = command.split_whitespace().collect();
        
        if let Some(cmd) = parts.first() {
            read_only_commands.contains(cmd)
        } else {
            false
        }
    }
}

impl PermissionChecker {
    fn new() -> Self {
        let dangerous_permissions = vec![
            "777".to_string(),
            "666".to_string(),
            "+s".to_string(), // setuid/setgid
        ];
        
        let mut safe_operations = HashMap::new();
        safe_operations.insert("chmod".to_string(), vec![
            "644".to_string(),
            "755".to_string(),
            "600".to_string(),
            "700".to_string(),
        ]);
        
        Self { dangerous_permissions, safe_operations }
    }
    
    fn check(&self, command: &str) -> Result<Vec<String>> {
        let mut warnings = vec![];
        
        if command.contains("chmod") {
            for perm in &self.dangerous_permissions {
                if command.contains(perm) {
                    warnings.push(format!("Dangerous permission: {}", perm));
                }
            }
        }
        
        if command.contains("chown") && command.contains("root") {
            warnings.push("Changing ownership to root".to_string());
        }
        
        Ok(warnings)
    }
}

impl CommandSanitizer {
    fn new() -> Self {
        let dangerous_patterns = vec![
            Regex::new(r"\$\(.*\)").unwrap(), // Command substitution
            Regex::new(r"`.*`").unwrap(),     // Backticks
            Regex::new(r";\s*rm").unwrap(),   // rm after semicolon
            Regex::new(r"&&\s*rm").unwrap(),  // rm after &&
            Regex::new(r"\|\s*sh").unwrap(),  // Pipe to shell
        ];
        
        let escape_sequences = vec![
            Regex::new(r"\\x[0-9a-fA-F]{2}").unwrap(),
            Regex::new(r"\\[0-7]{3}").unwrap(),
        ];
        
        let mut safe_replacements = HashMap::new();
        safe_replacements.insert("rm -rf".to_string(), "rm -i".to_string());
        safe_replacements.insert("chmod 777".to_string(), "chmod 755".to_string());
        
        Self {
            dangerous_patterns,
            escape_sequences,
            safe_replacements,
        }
    }
    
    fn sanitize(&self, command: &str) -> Result<(String, Vec<String>)> {
        let mut sanitized = command.to_string();
        let mut warnings = vec![];
        
        // Check for dangerous patterns
        for pattern in &self.dangerous_patterns {
            if pattern.is_match(&sanitized) {
                warnings.push(format!("Dangerous pattern detected: {}", pattern.as_str()));
            }
        }
        
        // Check for escape sequences
        for pattern in &self.escape_sequences {
            if pattern.is_match(&sanitized) {
                warnings.push("Escape sequences detected".to_string());
                sanitized = pattern.replace_all(&sanitized, "").to_string();
            }
        }
        
        // Apply safe replacements
        for (dangerous, safe) in &self.safe_replacements {
            if sanitized.contains(dangerous) {
                warnings.push(format!("Replacing '{}' with '{}'", dangerous, safe));
                sanitized = sanitized.replace(dangerous, safe);
            }
        }
        
        Ok((sanitized, warnings))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommandExecution {
    pub command: String,
    pub exit_code: i32,
    pub had_errors: bool,
    pub was_destructive: bool,
    pub error_message: String,
}