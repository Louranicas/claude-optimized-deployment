//! Capability mapper for MCP tools
//! 
//! Maps bash command capabilities to MCP tool capabilities

use crate::synthex_bashgod::{Result, SBGError};
use crate::synthex_bashgod::mcp_integration::{MCPTool, ServerType};
use dashmap::DashMap;
use std::sync::Arc;
use tracing::{debug, info};

/// Capability mapper for MCP tools
pub struct CapabilityMapper {
    /// Capability mappings
    mappings: Arc<DashMap<String, Vec<MCPCapability>>>,
    
    /// Reverse mappings (MCP to bash)
    reverse_mappings: Arc<DashMap<String, Vec<String>>>,
    
    /// Capability requirements
    requirements: Arc<DashMap<String, CapabilityRequirements>>,
}

/// MCP capability
#[derive(Debug, Clone)]
pub struct MCPCapability {
    /// Server type
    pub server: ServerType,
    
    /// Tool name
    pub tool: String,
    
    /// Capability name
    pub capability: String,
    
    /// Required permissions
    pub permissions: Vec<String>,
    
    /// Performance characteristics
    pub performance: PerformanceProfile,
}

/// Performance profile for capability
#[derive(Debug, Clone)]
pub struct PerformanceProfile {
    /// Average execution time
    pub avg_time_ms: u64,
    
    /// Resource intensity (0.0 to 1.0)
    pub resource_intensity: f32,
    
    /// Reliability score (0.0 to 1.0)
    pub reliability: f32,
    
    /// Scalability factor
    pub scalability: ScalabilityFactor,
}

/// Scalability characteristics
#[derive(Debug, Clone)]
pub enum ScalabilityFactor {
    /// Constant time
    Constant,
    
    /// Linear with input size
    Linear,
    
    /// Logarithmic
    Logarithmic,
    
    /// Quadratic or worse
    Quadratic,
}

/// Capability requirements
#[derive(Debug, Clone)]
pub struct CapabilityRequirements {
    /// Required system resources
    pub resources: ResourceRequirements,
    
    /// Required permissions
    pub permissions: Vec<Permission>,
    
    /// Dependencies
    pub dependencies: Vec<String>,
    
    /// Constraints
    pub constraints: Vec<Constraint>,
}

/// Resource requirements
#[derive(Debug, Clone)]
pub struct ResourceRequirements {
    /// Minimum CPU cores
    pub min_cpu_cores: Option<f32>,
    
    /// Minimum memory in MB
    pub min_memory_mb: Option<u64>,
    
    /// Required disk space in MB
    pub min_disk_mb: Option<u64>,
    
    /// Network access required
    pub network_required: bool,
}

/// Permission types
#[derive(Debug, Clone)]
pub enum Permission {
    /// File system read
    FileSystemRead(String),
    
    /// File system write
    FileSystemWrite(String),
    
    /// Network access
    NetworkAccess(Vec<String>),
    
    /// Process management
    ProcessManagement,
    
    /// System configuration
    SystemConfiguration,
    
    /// Container management
    ContainerManagement,
    
    /// Cloud resources
    CloudResources(String),
}

/// Constraint types
#[derive(Debug, Clone)]
pub enum Constraint {
    /// Operating system
    OperatingSystem(Vec<String>),
    
    /// Architecture
    Architecture(Vec<String>),
    
    /// Tool version
    ToolVersion { tool: String, min_version: String },
    
    /// Feature flag
    FeatureFlag(String),
}

impl CapabilityMapper {
    /// Create new capability mapper
    pub fn new() -> Self {
        let mut mapper = Self {
            mappings: Arc::new(DashMap::new()),
            reverse_mappings: Arc::new(DashMap::new()),
            requirements: Arc::new(DashMap::new()),
        };
        
        // Initialize default mappings
        mapper.init_default_mappings();
        
        mapper
    }
    
    /// Initialize default capability mappings
    fn init_default_mappings(&mut self) {
        // Docker capabilities
        self.add_docker_capabilities();
        
        // Kubernetes capabilities
        self.add_kubernetes_capabilities();
        
        // Git capabilities
        self.add_git_capabilities();
        
        // File system capabilities
        self.add_filesystem_capabilities();
    }
    
    /// Add Docker capability mappings
    fn add_docker_capabilities(&mut self) {
        let docker_caps = vec![
            MCPCapability {
                server: ServerType::Docker,
                tool: "containers".to_string(),
                capability: "list".to_string(),
                permissions: vec!["docker.list".to_string()],
                performance: PerformanceProfile {
                    avg_time_ms: 100,
                    resource_intensity: 0.2,
                    reliability: 0.99,
                    scalability: ScalabilityFactor::Linear,
                },
            },
            MCPCapability {
                server: ServerType::Docker,
                tool: "containers".to_string(),
                capability: "run".to_string(),
                permissions: vec!["docker.run".to_string()],
                performance: PerformanceProfile {
                    avg_time_ms: 2000,
                    resource_intensity: 0.8,
                    reliability: 0.95,
                    scalability: ScalabilityFactor::Constant,
                },
            },
            MCPCapability {
                server: ServerType::Docker,
                tool: "images".to_string(),
                capability: "list".to_string(),
                permissions: vec!["docker.images.list".to_string()],
                performance: PerformanceProfile {
                    avg_time_ms: 150,
                    resource_intensity: 0.3,
                    reliability: 0.99,
                    scalability: ScalabilityFactor::Linear,
                },
            },
        ];
        
        // Add mappings
        self.mappings.insert("docker ps".to_string(), vec![docker_caps[0].clone()]);
        self.mappings.insert("docker run".to_string(), vec![docker_caps[1].clone()]);
        self.mappings.insert("docker images".to_string(), vec![docker_caps[2].clone()]);
        
        // Add reverse mappings
        self.reverse_mappings.insert("docker.containers.list".to_string(), vec!["docker ps".to_string()]);
        self.reverse_mappings.insert("docker.containers.run".to_string(), vec!["docker run".to_string()]);
        self.reverse_mappings.insert("docker.images.list".to_string(), vec!["docker images".to_string()]);
        
        // Add requirements
        self.requirements.insert(
            "docker".to_string(),
            CapabilityRequirements {
                resources: ResourceRequirements {
                    min_cpu_cores: Some(0.5),
                    min_memory_mb: Some(512),
                    min_disk_mb: Some(1024),
                    network_required: true,
                },
                permissions: vec![Permission::ContainerManagement],
                dependencies: vec!["docker".to_string()],
                constraints: vec![
                    Constraint::OperatingSystem(vec!["linux".to_string(), "darwin".to_string()]),
                ],
            },
        );
    }
    
    /// Add Kubernetes capability mappings
    fn add_kubernetes_capabilities(&mut self) {
        let k8s_caps = vec![
            MCPCapability {
                server: ServerType::Kubernetes,
                tool: "pods".to_string(),
                capability: "list".to_string(),
                permissions: vec!["k8s.pods.list".to_string()],
                performance: PerformanceProfile {
                    avg_time_ms: 200,
                    resource_intensity: 0.3,
                    reliability: 0.98,
                    scalability: ScalabilityFactor::Linear,
                },
            },
            MCPCapability {
                server: ServerType::Kubernetes,
                tool: "services".to_string(),
                capability: "list".to_string(),
                permissions: vec!["k8s.services.list".to_string()],
                performance: PerformanceProfile {
                    avg_time_ms: 150,
                    resource_intensity: 0.2,
                    reliability: 0.98,
                    scalability: ScalabilityFactor::Linear,
                },
            },
        ];
        
        self.mappings.insert("kubectl get pods".to_string(), vec![k8s_caps[0].clone()]);
        self.mappings.insert("kubectl get services".to_string(), vec![k8s_caps[1].clone()]);
    }
    
    /// Add Git capability mappings
    fn add_git_capabilities(&mut self) {
        let git_caps = vec![
            MCPCapability {
                server: ServerType::Git,
                tool: "repository".to_string(),
                capability: "status".to_string(),
                permissions: vec!["git.read".to_string()],
                performance: PerformanceProfile {
                    avg_time_ms: 50,
                    resource_intensity: 0.1,
                    reliability: 0.99,
                    scalability: ScalabilityFactor::Constant,
                },
            },
            MCPCapability {
                server: ServerType::Git,
                tool: "repository".to_string(),
                capability: "log".to_string(),
                permissions: vec!["git.read".to_string()],
                performance: PerformanceProfile {
                    avg_time_ms: 100,
                    resource_intensity: 0.2,
                    reliability: 0.99,
                    scalability: ScalabilityFactor::Linear,
                },
            },
        ];
        
        self.mappings.insert("git status".to_string(), vec![git_caps[0].clone()]);
        self.mappings.insert("git log".to_string(), vec![git_caps[1].clone()]);
    }
    
    /// Add file system capability mappings
    fn add_filesystem_capabilities(&mut self) {
        let fs_caps = vec![
            MCPCapability {
                server: ServerType::Filesystem,
                tool: "files".to_string(),
                capability: "search".to_string(),
                permissions: vec!["fs.read".to_string()],
                performance: PerformanceProfile {
                    avg_time_ms: 500,
                    resource_intensity: 0.6,
                    reliability: 0.99,
                    scalability: ScalabilityFactor::Linear,
                },
            },
            MCPCapability {
                server: ServerType::Filesystem,
                tool: "files".to_string(),
                capability: "list".to_string(),
                permissions: vec!["fs.read".to_string()],
                performance: PerformanceProfile {
                    avg_time_ms: 100,
                    resource_intensity: 0.2,
                    reliability: 0.99,
                    scalability: ScalabilityFactor::Linear,
                },
            },
        ];
        
        self.mappings.insert("find".to_string(), vec![fs_caps[0].clone()]);
        self.mappings.insert("ls".to_string(), vec![fs_caps[1].clone()]);
    }
    
    /// Map bash command to MCP capabilities
    pub fn map_command(&self, command: &str) -> Vec<MCPCapability> {
        // Find exact match first
        if let Some(caps) = self.mappings.get(command) {
            return caps.clone();
        }
        
        // Try prefix matching
        for entry in self.mappings.iter() {
            if command.starts_with(entry.key()) {
                return entry.value().clone();
            }
        }
        
        // No mapping found
        Vec::new()
    }
    
    /// Get bash equivalents for MCP capability
    pub fn get_bash_equivalents(&self, mcp_capability: &str) -> Vec<String> {
        self.reverse_mappings
            .get(mcp_capability)
            .map(|cmds| cmds.clone())
            .unwrap_or_default()
    }
    
    /// Check if capability requirements are met
    pub fn check_requirements(
        &self,
        capability: &MCPCapability,
        available_resources: &ResourceRequirements,
    ) -> Result<()> {
        let key = match &capability.server {
            ServerType::Docker => "docker",
            ServerType::Kubernetes => "kubernetes",
            ServerType::Git => "git",
            ServerType::Filesystem => "filesystem",
            ServerType::Database => "database",
            ServerType::Cloud(provider) => provider.as_str(),
            ServerType::Custom(name) => name.as_str(),
        };
        
        if let Some(requirements) = self.requirements.get(key) {
            // Check CPU
            if let Some(min_cpu) = requirements.resources.min_cpu_cores {
                if let Some(available_cpu) = available_resources.min_cpu_cores {
                    if available_cpu < min_cpu {
                        return Err(SBGError::MCPError(
                            format!("Insufficient CPU: {} < {}", available_cpu, min_cpu)
                        ));
                    }
                }
            }
            
            // Check memory
            if let Some(min_mem) = requirements.resources.min_memory_mb {
                if let Some(available_mem) = available_resources.min_memory_mb {
                    if available_mem < min_mem {
                        return Err(SBGError::MCPError(
                            format!("Insufficient memory: {} MB < {} MB", available_mem, min_mem)
                        ));
                    }
                }
            }
            
            // Check network
            if requirements.resources.network_required && !available_resources.network_required {
                return Err(SBGError::MCPError("Network access required but not available".to_string()));
            }
        }
        
        Ok(())
    }
    
    /// Get optimal capability for a command
    pub fn get_optimal_capability(&self, command: &str) -> Option<MCPCapability> {
        let capabilities = self.map_command(command);
        
        // Sort by performance score
        let mut sorted_caps = capabilities;
        sorted_caps.sort_by(|a, b| {
            let score_a = self.calculate_performance_score(&a.performance);
            let score_b = self.calculate_performance_score(&b.performance);
            score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        sorted_caps.into_iter().next()
    }
    
    /// Calculate performance score
    fn calculate_performance_score(&self, profile: &PerformanceProfile) -> f32 {
        let time_score = 1.0 / (1.0 + profile.avg_time_ms as f32 / 1000.0);
        let efficiency_score = 1.0 - profile.resource_intensity;
        let reliability_score = profile.reliability;
        
        let scalability_score = match profile.scalability {
            ScalabilityFactor::Constant => 1.0,
            ScalabilityFactor::Logarithmic => 0.8,
            ScalabilityFactor::Linear => 0.6,
            ScalabilityFactor::Quadratic => 0.3,
        };
        
        // Weighted average
        (time_score * 0.3 + efficiency_score * 0.2 + reliability_score * 0.3 + scalability_score * 0.2)
    }
    
    /// Add custom capability mapping
    pub fn add_mapping(&self, bash_command: String, capability: MCPCapability) {
        self.mappings.entry(bash_command.clone())
            .or_insert_with(Vec::new)
            .push(capability.clone());
        
        let mcp_key = format!("{:?}.{}.{}", capability.server, capability.tool, capability.capability);
        self.reverse_mappings.entry(mcp_key)
            .or_insert_with(Vec::new)
            .push(bash_command);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_capability_mapping() {
        let mapper = CapabilityMapper::new();
        
        // Test Docker mapping
        let caps = mapper.map_command("docker ps");
        assert!(!caps.is_empty());
        assert_eq!(caps[0].tool, "containers");
        assert_eq!(caps[0].capability, "list");
        
        // Test Git mapping
        let caps = mapper.map_command("git status");
        assert!(!caps.is_empty());
        assert_eq!(caps[0].tool, "repository");
        assert_eq!(caps[0].capability, "status");
    }
    
    #[test]
    fn test_reverse_mapping() {
        let mapper = CapabilityMapper::new();
        
        let bash_cmds = mapper.get_bash_equivalents("docker.containers.list");
        assert!(!bash_cmds.is_empty());
        assert_eq!(bash_cmds[0], "docker ps");
    }
    
    #[test]
    fn test_performance_scoring() {
        let mapper = CapabilityMapper::new();
        
        let profile = PerformanceProfile {
            avg_time_ms: 100,
            resource_intensity: 0.3,
            reliability: 0.95,
            scalability: ScalabilityFactor::Linear,
        };
        
        let score = mapper.calculate_performance_score(&profile);
        assert!(score > 0.0 && score <= 1.0);
    }
    
    #[test]
    fn test_requirement_checking() {
        let mapper = CapabilityMapper::new();
        
        let capability = MCPCapability {
            server: ServerType::Docker,
            tool: "containers".to_string(),
            capability: "list".to_string(),
            permissions: vec![],
            performance: PerformanceProfile {
                avg_time_ms: 100,
                resource_intensity: 0.2,
                reliability: 0.99,
                scalability: ScalabilityFactor::Linear,
            },
        };
        
        let available = ResourceRequirements {
            min_cpu_cores: Some(2.0),
            min_memory_mb: Some(2048),
            min_disk_mb: Some(10240),
            network_required: true,
        };
        
        assert!(mapper.check_requirements(&capability, &available).is_ok());
    }
}