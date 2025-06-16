use std::sync::Arc;
use parking_lot::RwLock;
use dashmap::DashMap;
use lru::LruCache;
use std::num::NonZeroUsize;
use anyhow::{Result, anyhow};

const ONE_GB: usize = 1_073_741_824;
const COMMAND_PATTERN_CACHE_SIZE: usize = 10_000;
const SYSTEM_STATE_CACHE_SIZE: usize = 1_000;

pub struct MemoryPool {
    total_size: usize,
    used_size: Arc<RwLock<usize>>,
    command_patterns: Arc<DashMap<String, CommandPattern>>,
    system_states: Arc<RwLock<LruCache<String, SystemStateSnapshot>>>,
    safety_rules: Arc<DashMap<String, SafetyRule>>,
    optimization_hints: Arc<DashMap<String, OptimizationHint>>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CommandPattern {
    pub pattern: String,
    pub frequency: u64,
    pub success_rate: f64,
    pub average_duration_ms: u64,
    pub contexts: Vec<String>,
    pub optimizations: Vec<String>,
    pub size_bytes: usize,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SystemStateSnapshot {
    pub timestamp: i64,
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub disk_usage: Vec<DiskUsage>,
    pub active_processes: u32,
    pub network_state: NetworkState,
    pub size_bytes: usize,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DiskUsage {
    pub mount_point: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub filesystem: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NetworkState {
    pub interfaces: Vec<String>,
    pub active_connections: u32,
    pub bandwidth_usage: f32,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SafetyRule {
    pub rule_id: String,
    pub pattern: String,
    pub risk_level: RiskLevel,
    pub mitigations: Vec<String>,
    pub size_bytes: usize,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OptimizationHint {
    pub hint_id: String,
    pub original_pattern: String,
    pub optimized_pattern: String,
    pub improvement_factor: f64,
    pub conditions: Vec<String>,
    pub size_bytes: usize,
}

impl MemoryPool {
    pub fn new() -> Result<Self> {
        let system_states = LruCache::new(
            NonZeroUsize::new(SYSTEM_STATE_CACHE_SIZE)
                .ok_or_else(|| anyhow!("Invalid cache size"))?
        );
        
        Ok(Self {
            total_size: ONE_GB,
            used_size: Arc::new(RwLock::new(0)),
            command_patterns: Arc::new(DashMap::new()),
            system_states: Arc::new(RwLock::new(system_states)),
            safety_rules: Arc::new(DashMap::new()),
            optimization_hints: Arc::new(DashMap::new()),
        })
    }
    
    pub fn allocate(&self, size: usize) -> Result<()> {
        let mut used = self.used_size.write();
        if *used + size > self.total_size {
            return Err(anyhow!("Memory pool exhausted: requested {} bytes, available {} bytes", 
                size, self.total_size - *used));
        }
        *used += size;
        Ok(())
    }
    
    pub fn deallocate(&self, size: usize) {
        let mut used = self.used_size.write();
        *used = used.saturating_sub(size);
    }
    
    pub fn store_command_pattern(&self, key: String, pattern: CommandPattern) -> Result<()> {
        let size = pattern.size_bytes;
        self.allocate(size)?;
        
        if let Some(old) = self.command_patterns.insert(key.clone(), pattern) {
            self.deallocate(old.size_bytes);
        }
        
        Ok(())
    }
    
    pub fn get_command_pattern(&self, key: &str) -> Option<CommandPattern> {
        self.command_patterns.get(key).map(|p| p.clone())
    }
    
    pub fn update_command_pattern<F>(&self, key: &str, updater: F) -> Result<()>
    where
        F: FnOnce(&mut CommandPattern),
    {
        if let Some(mut pattern) = self.command_patterns.get_mut(key) {
            let old_size = pattern.size_bytes;
            updater(&mut pattern);
            let size_diff = pattern.size_bytes as i64 - old_size as i64;
            
            if size_diff > 0 {
                self.allocate(size_diff as usize)?;
            } else if size_diff < 0 {
                self.deallocate((-size_diff) as usize);
            }
        }
        Ok(())
    }
    
    pub fn store_system_state(&self, key: String, state: SystemStateSnapshot) -> Result<()> {
        let size = state.size_bytes;
        self.allocate(size)?;
        
        let mut states = self.system_states.write();
        if let Some(old) = states.push(key, state) {
            self.deallocate(old.size_bytes);
        }
        
        Ok(())
    }
    
    pub fn get_recent_system_states(&self, count: usize) -> Vec<SystemStateSnapshot> {
        let states = self.system_states.read();
        states.iter()
            .take(count)
            .map(|(_, state)| state.clone())
            .collect()
    }
    
    pub fn store_safety_rule(&self, rule: SafetyRule) -> Result<()> {
        let size = rule.size_bytes;
        self.allocate(size)?;
        
        let key = rule.rule_id.clone();
        if let Some(old) = self.safety_rules.insert(key, rule) {
            self.deallocate(old.size_bytes);
        }
        
        Ok(())
    }
    
    pub fn get_safety_rules(&self) -> Vec<SafetyRule> {
        self.safety_rules.iter()
            .map(|entry| entry.value().clone())
            .collect()
    }
    
    pub fn store_optimization_hint(&self, hint: OptimizationHint) -> Result<()> {
        let size = hint.size_bytes;
        self.allocate(size)?;
        
        let key = hint.hint_id.clone();
        if let Some(old) = self.optimization_hints.insert(key, hint) {
            self.deallocate(old.size_bytes);
        }
        
        Ok(())
    }
    
    pub fn find_optimization_hints(&self, pattern: &str) -> Vec<OptimizationHint> {
        self.optimization_hints.iter()
            .filter(|entry| entry.value().original_pattern.contains(pattern))
            .map(|entry| entry.value().clone())
            .collect()
    }
    
    pub fn get_memory_stats(&self) -> MemoryStats {
        let used = *self.used_size.read();
        MemoryStats {
            total_bytes: self.total_size,
            used_bytes: used,
            available_bytes: self.total_size - used,
            command_patterns_count: self.command_patterns.len(),
            safety_rules_count: self.safety_rules.len(),
            optimization_hints_count: self.optimization_hints.len(),
            usage_percentage: (used as f64 / self.total_size as f64) * 100.0,
        }
    }
    
    pub fn garbage_collect(&self) -> Result<usize> {
        let mut freed = 0;
        
        // Remove low-frequency command patterns
        let patterns_to_remove: Vec<String> = self.command_patterns.iter()
            .filter(|entry| entry.value().frequency < 2 && entry.value().success_rate < 0.5)
            .map(|entry| entry.key().clone())
            .collect();
        
        for key in patterns_to_remove {
            if let Some((_, pattern)) = self.command_patterns.remove(&key) {
                freed += pattern.size_bytes;
                self.deallocate(pattern.size_bytes);
            }
        }
        
        // Remove old optimization hints with low improvement
        let hints_to_remove: Vec<String> = self.optimization_hints.iter()
            .filter(|entry| entry.value().improvement_factor < 1.1)
            .map(|entry| entry.key().clone())
            .collect();
        
        for key in hints_to_remove {
            if let Some((_, hint)) = self.optimization_hints.remove(&key) {
                freed += hint.size_bytes;
                self.deallocate(hint.size_bytes);
            }
        }
        
        Ok(freed)
    }
}

#[derive(Debug, serde::Serialize)]
pub struct MemoryStats {
    pub total_bytes: usize,
    pub used_bytes: usize,
    pub available_bytes: usize,
    pub command_patterns_count: usize,
    pub safety_rules_count: usize,
    pub optimization_hints_count: usize,
    pub usage_percentage: f64,
}

impl CommandPattern {
    pub fn calculate_size(&mut self) {
        self.size_bytes = std::mem::size_of_val(self) +
            self.pattern.len() +
            self.contexts.iter().map(|c| c.len()).sum::<usize>() +
            self.optimizations.iter().map(|o| o.len()).sum::<usize>();
    }
}

impl SystemStateSnapshot {
    pub fn calculate_size(&mut self) {
        self.size_bytes = std::mem::size_of_val(self) +
            self.disk_usage.iter()
                .map(|d| std::mem::size_of_val(d) + d.mount_point.len() + d.filesystem.len())
                .sum::<usize>() +
            self.network_state.interfaces.iter().map(|i| i.len()).sum::<usize>();
    }
}

impl SafetyRule {
    pub fn calculate_size(&mut self) {
        self.size_bytes = std::mem::size_of_val(self) +
            self.rule_id.len() +
            self.pattern.len() +
            self.mitigations.iter().map(|m| m.len()).sum::<usize>();
    }
}

impl OptimizationHint {
    pub fn calculate_size(&mut self) {
        self.size_bytes = std::mem::size_of_val(self) +
            self.hint_id.len() +
            self.original_pattern.len() +
            self.optimized_pattern.len() +
            self.conditions.iter().map(|c| c.len()).sum::<usize>();
    }
}