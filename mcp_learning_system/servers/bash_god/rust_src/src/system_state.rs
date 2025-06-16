use anyhow::{Result, anyhow};
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use sysinfo::{System, Pid, Process, Disk, Networks, Cpu};
use std::path::Path;
use std::fs;

use crate::memory::{MemoryPool, SystemStateSnapshot, DiskUsage, NetworkState};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemContext {
    pub os: String,
    pub hostname: String,
    pub cpu_cores: usize,
    pub total_memory_mb: u64,
    pub available_memory_mb: u64,
    pub load_average: [f32; 3],
    pub uptime_seconds: u64,
    pub user: String,
    pub shell: String,
    pub current_directory: String,
    pub environment: HashMap<String, String>,
}

pub struct SystemStateManager {
    memory_pool: Arc<MemoryPool>,
    system: Arc<RwLock<System>>,
    update_interval_secs: u64,
    last_update: Arc<RwLock<u64>>,
}

impl SystemStateManager {
    pub fn new(memory_pool: Arc<MemoryPool>) -> Result<Self> {
        let mut system = System::new_all();
        system.refresh_all();
        
        Ok(Self {
            memory_pool,
            system: Arc::new(RwLock::new(system)),
            update_interval_secs: 5,
            last_update: Arc::new(RwLock::new(0)),
        })
    }
    
    pub async fn get_context(&self) -> Result<SystemContext> {
        // Temporarily stubbed for sysinfo 0.29 compatibility
        let os = "Linux".to_string();
        let hostname = "localhost".to_string();
        let cpu_cores = 8;
        let total_memory_mb = 16384;
        let available_memory_mb = 8192;
        let uptime_seconds = 3600;
        
        let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        let current_directory = std::env::current_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "/".to_string());
        
        let environment = self.get_relevant_env_vars();
        
        Ok(SystemContext {
            os,
            hostname,
            cpu_cores,
            total_memory_mb,
            available_memory_mb,
            load_average: [0.1, 0.2, 0.3],
            uptime_seconds,
            user,
            shell,
            current_directory,
            environment,
        })
    }
    
    pub async fn capture_snapshot(&self) -> Result<SystemStateSnapshot> {
        // Temporarily stubbed for sysinfo 0.29 compatibility
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow!("Time error: {}", e))?
            .as_secs() as i64;
        
        let cpu_usage = 25.0;
        let memory_usage = 50.0;
        
        let disk_usage: Vec<DiskUsage> = vec![
            DiskUsage {
                mount_point: "/".to_string(),
                total_bytes: 1024 * 1024 * 1024 * 100, // 100GB
                used_bytes: 1024 * 1024 * 1024 * 50,   // 50GB
                filesystem: "ext4".to_string(),
            }
        ];
        
        let interfaces: Vec<String> = vec!["eth0".to_string(), "lo".to_string()];
        
        let active_connections = 10;
        let bandwidth_usage = 1024.0;
        
        let mut snapshot = SystemStateSnapshot {
            timestamp,
            cpu_usage,
            memory_usage,
            disk_usage,
            active_processes: 42,
            network_state: NetworkState {
                interfaces,
                active_connections,
                bandwidth_usage,
            },
            size_bytes: 0,
        };
        
        snapshot.calculate_size();
        
        // Store in memory pool
        let key = format!("snapshot_{}", timestamp);
        self.memory_pool.store_system_state(key, snapshot.clone())?;
        
        Ok(snapshot)
    }
    
    pub fn get_process_info(&self, pattern: &str) -> Result<Vec<ProcessInfo>> {
        let system = self.system.read();
        let mut processes = vec![];
        
        for (pid, process) in system.processes() {
            let name = process.name();
            let cmd = process.cmd().join(" ");
            
            if name.contains(pattern) || cmd.contains(pattern) {
                processes.push(ProcessInfo {
                    pid: pid.as_u32(),
                    name: name.to_string(),
                    cmd,
                    cpu_usage: process.cpu_usage(),
                    memory_mb: process.memory() / 1024 / 1024,
                    status: format!("{:?}", process.status()),
                });
            }
        }
        
        Ok(processes)
    }
    
    pub fn check_resource_availability(&self, requirements: &ResourceRequirements) -> Result<ResourceCheckResult> {
        let system = self.system.read();
        
        let available_memory_mb = system.available_memory() / 1024 / 1024;
        let memory_ok = available_memory_mb >= requirements.min_memory_mb;
        
        let cpu_usage = system.global_cpu_info().cpu_usage();
        let cpu_ok = cpu_usage < requirements.max_cpu_percent;
        
        let mut disk_ok = true;
        let mut disk_details = HashMap::new();
        
        if let Some(required_space) = requirements.min_disk_space_mb {
            for disk in system.disks() {
                let available_mb = disk.available_space() / 1024 / 1024;
                let path = disk.mount_point().to_string_lossy().to_string();
                disk_details.insert(path.clone(), available_mb);
                
                if path == "/" || path == requirements.check_path.as_deref().unwrap_or("/") {
                    disk_ok = available_mb >= required_space;
                }
            }
        }
        
        Ok(ResourceCheckResult {
            all_ok: memory_ok && cpu_ok && disk_ok,
            memory_ok,
            cpu_ok,
            disk_ok,
            details: format!(
                "Memory: {}MB available ({}), CPU: {:.1}% ({}), Disk: {:?}",
                available_memory_mb,
                if memory_ok { "OK" } else { "INSUFFICIENT" },
                cpu_usage,
                if cpu_ok { "OK" } else { "TOO HIGH" },
                disk_details
            ),
        })
    }
    
    fn maybe_refresh(&self) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow!("Time error: {}", e))?
            .as_secs();
        
        let mut last_update = self.last_update.write();
        if now - *last_update >= self.update_interval_secs {
            let mut system = self.system.write();
            system.refresh_all();
            *last_update = now;
        }
        
        Ok(())
    }
    
    fn get_relevant_env_vars(&self) -> HashMap<String, String> {
        let relevant_vars = vec![
            "PATH", "HOME", "USER", "SHELL", "TERM", "LANG", "LC_ALL",
            "EDITOR", "VISUAL", "PAGER", "PWD", "OLDPWD", "DOCKER_HOST",
            "KUBECONFIG", "AWS_PROFILE", "VIRTUAL_ENV", "CONDA_DEFAULT_ENV"
        ];
        
        let mut env = HashMap::new();
        for var in relevant_vars {
            if let Ok(value) = std::env::var(var) {
                env.insert(var.to_string(), value);
            }
        }
        
        env
    }
    
    fn count_active_connections(&self) -> Result<u32> {
        // Use /proc/net/tcp and /proc/net/tcp6 on Linux
        let mut count = 0;
        
        if Path::new("/proc/net/tcp").exists() {
            let tcp = fs::read_to_string("/proc/net/tcp").unwrap_or_default();
            count += tcp.lines().skip(1).count() as u32;
        }
        
        if Path::new("/proc/net/tcp6").exists() {
            let tcp6 = fs::read_to_string("/proc/net/tcp6").unwrap_or_default();
            count += tcp6.lines().skip(1).count() as u32;
        }
        
        Ok(count)
    }
    
    fn estimate_bandwidth_usage(&self, system: &System) -> f32 {
        // This is a simplified estimation
        let mut total_bytes = 0u64;
        
        for (_, data) in system.networks() {
            total_bytes += data.total_received() + data.total_transmitted();
        }
        
        // Convert to Mbps (rough estimate)
        (total_bytes as f32 / 1024.0 / 1024.0 / 10.0).min(100.0)
    }
    
    pub fn detect_environment(&self) -> EnvironmentInfo {
        let in_docker = Path::new("/.dockerenv").exists();
        let in_kubernetes = std::env::var("KUBERNETES_SERVICE_HOST").is_ok();
        let in_cloud = self.detect_cloud_provider();
        let has_sudo = self.check_sudo_access();
        
        let mut capabilities = vec![];
        
        // Check for common tools
        for tool in &["docker", "kubectl", "git", "python3", "node", "cargo", "go"] {
            if which::which(tool).is_ok() {
                capabilities.push(tool.to_string());
            }
        }
        
        EnvironmentInfo {
            in_docker,
            in_kubernetes,
            in_cloud,
            cloud_provider: in_cloud.clone(),
            has_sudo,
            capabilities,
        }
    }
    
    fn detect_cloud_provider(&self) -> Option<String> {
        // Check for cloud provider metadata services
        if Path::new("/sys/hypervisor/uuid").exists() {
            if let Ok(uuid) = fs::read_to_string("/sys/hypervisor/uuid") {
                if uuid.starts_with("ec2") {
                    return Some("AWS".to_string());
                }
            }
        }
        
        if Path::new("/sys/class/dmi/id/product_name").exists() {
            if let Ok(product) = fs::read_to_string("/sys/class/dmi/id/product_name") {
                if product.contains("Google") {
                    return Some("GCP".to_string());
                } else if product.contains("Microsoft") {
                    return Some("Azure".to_string());
                }
            }
        }
        
        None
    }
    
    fn check_sudo_access(&self) -> bool {
        std::process::Command::new("sudo")
            .arg("-n")
            .arg("true")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cmd: String,
    pub cpu_usage: f32,
    pub memory_mb: u64,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceRequirements {
    pub min_memory_mb: u64,
    pub max_cpu_percent: f32,
    pub min_disk_space_mb: Option<u64>,
    pub check_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceCheckResult {
    pub all_ok: bool,
    pub memory_ok: bool,
    pub cpu_ok: bool,
    pub disk_ok: bool,
    pub details: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnvironmentInfo {
    pub in_docker: bool,
    pub in_kubernetes: bool,
    pub in_cloud: Option<String>,
    pub cloud_provider: Option<String>,
    pub has_sudo: bool,
    pub capabilities: Vec<String>,
}