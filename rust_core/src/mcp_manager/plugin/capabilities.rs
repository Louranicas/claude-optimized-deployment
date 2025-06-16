//! Plugin Capabilities - The DNA of Extensibility
//!
//! This module defines and manages plugin capabilities with the precision
//! of a Swiss watchmaker. Every capability is a promise, every query an answer.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use semver::{Version};
use tracing::{debug, info, warn};

use super::{Capability, PluginError, Result};

/// Capability manager - tracks and resolves plugin capabilities
pub struct CapabilityManager {
    /// Capability registry
    registry: Arc<RwLock<CapabilityRegistry>>,
    
    /// Capability resolver
    resolver: Arc<CapabilityResolver>,
    
    /// Configuration
    config: CapabilityConfig,
}

/// Capability registry
struct CapabilityRegistry {
    /// All registered capabilities
    capabilities: HashMap<CapabilityId, CapabilityDefinition>,
    
    /// Providers for each capability
    providers: HashMap<CapabilityId, HashSet<String>>,
    
    /// Consumers for each capability
    consumers: HashMap<CapabilityId, HashSet<String>>,
    
    /// Capability namespaces
    namespaces: HashMap<String, NamespaceInfo>,
}

/// Capability identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CapabilityId {
    namespace: String,
    name: String,
}

impl From<&Capability> for CapabilityId {
    fn from(cap: &Capability) -> Self {
        Self {
            namespace: cap.namespace.clone(),
            name: cap.name.clone(),
        }
    }
}

/// Full capability definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityDefinition {
    /// Capability identity
    pub capability: Capability,
    
    /// Description
    pub description: String,
    
    /// Method signatures
    pub methods: Vec<MethodSignature>,
    
    /// Required permissions
    pub permissions: Vec<Permission>,
    
    /// Semantic version
    pub version: Version,
    
    /// Deprecation info
    pub deprecated: Option<DeprecationInfo>,
    
    /// Feature flags
    pub features: HashSet<String>,
}

/// Method signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodSignature {
    /// Method name
    pub name: String,
    
    /// Input schema (JSON Schema)
    pub input_schema: serde_json::Value,
    
    /// Output schema (JSON Schema)
    pub output_schema: serde_json::Value,
    
    /// Is this method async?
    pub is_async: bool,
    
    /// Method tags
    pub tags: Vec<String>,
}

/// Permission requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    /// Permission name
    pub name: String,
    
    /// Resource pattern
    pub resource: String,
    
    /// Actions allowed
    pub actions: Vec<String>,
}

/// Deprecation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeprecationInfo {
    /// When deprecated
    pub since_version: Version,
    
    /// Removal version
    pub remove_version: Option<Version>,
    
    /// Replacement capability
    pub replacement: Option<Capability>,
    
    /// Migration guide
    pub migration_guide: Option<String>,
}

/// Namespace information
#[derive(Debug, Clone)]
struct NamespaceInfo {
    /// Namespace name
    name: String,
    
    /// Description
    description: String,
    
    /// Owner plugin
    owner: Option<String>,
    
    /// Capabilities in this namespace
    capabilities: HashSet<String>,
}

/// Capability configuration
#[derive(Debug, Clone)]
pub struct CapabilityConfig {
    /// Allow capability overrides
    pub allow_overrides: bool,
    
    /// Require semantic versioning
    pub require_semver: bool,
    
    /// Maximum providers per capability
    pub max_providers: usize,
    
    /// Enable deprecation warnings
    pub deprecation_warnings: bool,
}

impl Default for CapabilityConfig {
    fn default() -> Self {
        Self {
            allow_overrides: false,
            require_semver: true,
            max_providers: 10,
            deprecation_warnings: true,
        }
    }
}

/// Capability resolver
struct CapabilityResolver {
    /// Resolution strategies
    strategies: Vec<Box<dyn ResolutionStrategy>>,
}

/// Resolution strategy trait
trait ResolutionStrategy: Send + Sync {
    /// Select best provider for a capability
    fn select_provider(
        &self,
        capability: &Capability,
        providers: &[ProviderInfo],
    ) -> Option<String>;
    
    /// Name of this strategy
    fn name(&self) -> &str;
}

/// Provider information
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    /// Provider plugin ID
    pub plugin_id: String,
    
    /// Capability version provided
    pub version: Version,
    
    /// Provider priority
    pub priority: i32,
    
    /// Load order
    pub load_order: usize,
    
    /// Health score (0-100)
    pub health_score: u8,
}

/// Version-based resolution strategy
struct VersionStrategy;

impl ResolutionStrategy for VersionStrategy {
    fn select_provider(
        &self,
        _capability: &Capability,
        providers: &[ProviderInfo],
    ) -> Option<String> {
        providers
            .iter()
            .max_by_key(|p| &p.version)
            .map(|p| p.plugin_id.clone())
    }
    
    fn name(&self) -> &str {
        "version"
    }
}

/// Priority-based resolution strategy
struct PriorityStrategy;

impl ResolutionStrategy for PriorityStrategy {
    fn select_provider(
        &self,
        _capability: &Capability,
        providers: &[ProviderInfo],
    ) -> Option<String> {
        providers
            .iter()
            .max_by_key(|p| (p.priority, p.health_score))
            .map(|p| p.plugin_id.clone())
    }
    
    fn name(&self) -> &str {
        "priority"
    }
}

impl CapabilityManager {
    /// Create a new capability manager
    pub fn new(config: CapabilityConfig) -> Self {
        let strategies: Vec<Box<dyn ResolutionStrategy>> = vec![
            Box::new(VersionStrategy),
            Box::new(PriorityStrategy),
        ];
        
        Self {
            registry: Arc::new(RwLock::new(CapabilityRegistry {
                capabilities: HashMap::new(),
                providers: HashMap::new(),
                consumers: HashMap::new(),
                namespaces: HashMap::new(),
            })),
            resolver: Arc::new(CapabilityResolver { strategies }),
            config,
        }
    }
    
    /// Register a capability definition
    pub async fn register_capability(&self, definition: CapabilityDefinition) -> Result<()> {
        let mut registry = self.registry.write().await;
        let cap_id = CapabilityId::from(&definition.capability);
        
        // Check if already registered
        if registry.capabilities.contains_key(&cap_id) && !self.config.allow_overrides {
            return Err(PluginError::AlreadyLoaded(
                format!("Capability {} already registered", definition.capability.to_string())
            ));
        }
        
        // Validate version if required
        if self.config.require_semver {
            // Version validation is done by semver crate
        }
        
        // Update namespace
        registry.namespaces
            .entry(definition.capability.namespace.clone())
            .or_insert_with(|| NamespaceInfo {
                name: definition.capability.namespace.clone(),
                description: String::new(),
                owner: None,
                capabilities: HashSet::new(),
            })
            .capabilities
            .insert(definition.capability.name.clone());
        
        // Store definition
        registry.capabilities.insert(cap_id.clone(), definition.clone());
        
        info!("Registered capability: {}", definition.capability.to_string());
        
        // Check for deprecation
        if self.config.deprecation_warnings {
            if let Some(dep) = &definition.deprecated {
                warn!(
                    "Capability {} is deprecated since version {}",
                    definition.capability.to_string(),
                    dep.since_version
                );
            }
        }
        
        Ok(())
    }
    
    /// Register a capability provider
    pub async fn register_provider(
        &self,
        plugin_id: String,
        capabilities: Vec<Capability>,
    ) -> Result<()> {
        let mut registry = self.registry.write().await;
        
        for capability in capabilities {
            let cap_id = CapabilityId::from(&capability);
            
            // Check provider limit
            let providers = registry.providers.entry(cap_id.clone()).or_default();
            if providers.len() >= self.config.max_providers {
                return Err(PluginError::InvalidManifest(
                    format!(
                        "Maximum providers ({}) reached for capability {}",
                        self.config.max_providers,
                        capability.to_string()
                    )
                ));
            }
            
            providers.insert(plugin_id.clone());
            
            debug!(
                "Plugin {} registered as provider for {}",
                plugin_id,
                capability.to_string()
            );
        }
        
        Ok(())
    }
    
    /// Register a capability consumer
    pub async fn register_consumer(
        &self,
        plugin_id: String,
        capabilities: Vec<Capability>,
    ) -> Result<()> {
        let mut registry = self.registry.write().await;
        
        for capability in capabilities {
            let cap_id = CapabilityId::from(&capability);
            registry.consumers
                .entry(cap_id)
                .or_default()
                .insert(plugin_id.clone());
        }
        
        Ok(())
    }
    
    /// Find provider for a capability
    pub async fn find_provider(&self, capability: &Capability) -> Result<Option<String>> {
        let registry = self.registry.read().await;
        let cap_id = CapabilityId::from(capability);
        
        // Get all providers
        let provider_ids = match registry.providers.get(&cap_id) {
            Some(providers) => providers,
            None => return Ok(None),
        };
        
        if provider_ids.is_empty() {
            return Ok(None);
        }
        
        // If only one provider, return it
        if provider_ids.len() == 1 {
            return Ok(provider_ids.iter().next().cloned());
        }
        
        // Multiple providers - need to resolve
        // This is simplified - in reality would need provider info
        let providers: Vec<ProviderInfo> = provider_ids
            .iter()
            .enumerate()
            .map(|(i, id)| ProviderInfo {
                plugin_id: id.clone(),
                version: Version::new(1, 0, 0), // Would get from plugin
                priority: 0,
                load_order: i,
                health_score: 100,
            })
            .collect();
        
        // Try resolution strategies
        for strategy in &self.resolver.strategies {
            if let Some(selected) = strategy.select_provider(capability, &providers) {
                debug!(
                    "Strategy '{}' selected provider {} for {}",
                    strategy.name(),
                    selected,
                    capability.to_string()
                );
                return Ok(Some(selected));
            }
        }
        
        // Fallback to first provider
        Ok(provider_ids.iter().next().cloned())
    }
    
    /// Get capability definition
    pub async fn get_definition(&self, capability: &Capability) -> Option<CapabilityDefinition> {
        let registry = self.registry.read().await;
        let cap_id = CapabilityId::from(capability);
        registry.capabilities.get(&cap_id).cloned()
    }
    
    /// List all capabilities
    pub async fn list_capabilities(&self) -> Vec<CapabilityDefinition> {
        let registry = self.registry.read().await;
        registry.capabilities.values().cloned().collect()
    }
    
    /// List capabilities by namespace
    pub async fn list_by_namespace(&self, namespace: &str) -> Vec<CapabilityDefinition> {
        let registry = self.registry.read().await;
        registry.capabilities
            .values()
            .filter(|def| def.capability.namespace == namespace)
            .cloned()
            .collect()
    }
    
    /// Get providers for a capability
    pub async fn get_providers(&self, capability: &Capability) -> Vec<String> {
        let registry = self.registry.read().await;
        let cap_id = CapabilityId::from(capability);
        registry.providers
            .get(&cap_id)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }
    
    /// Get consumers for a capability
    pub async fn get_consumers(&self, capability: &Capability) -> Vec<String> {
        let registry = self.registry.read().await;
        let cap_id = CapabilityId::from(capability);
        registry.consumers
            .get(&cap_id)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }
    
    /// Check if a capability is satisfied
    pub async fn is_satisfied(&self, capability: &Capability) -> bool {
        let registry = self.registry.read().await;
        let cap_id = CapabilityId::from(capability);
        
        registry.providers
            .get(&cap_id)
            .map(|providers| !providers.is_empty())
            .unwrap_or(false)
    }
    
    /// Validate capability requirements
    pub async fn validate_requirements(
        &self,
        required: &[Capability],
    ) -> Result<Vec<UnsatisfiedCapability>> {
        let mut unsatisfied = Vec::new();
        
        for capability in required {
            if !self.is_satisfied(capability).await {
                let alternatives = self.find_alternatives(capability).await;
                unsatisfied.push(UnsatisfiedCapability {
                    capability: capability.clone(),
                    reason: "No provider available".to_string(),
                    alternatives,
                });
            }
        }
        
        Ok(unsatisfied)
    }
    
    /// Find alternative capabilities
    async fn find_alternatives(&self, capability: &Capability) -> Vec<Capability> {
        let registry = self.registry.read().await;
        
        // Find capabilities in same namespace with similar names
        registry.capabilities
            .values()
            .filter(|def| {
                def.capability.namespace == capability.namespace
                    && def.capability.name.contains(&capability.name[..capability.name.len().min(3)])
                    && def.capability != *capability
            })
            .map(|def| def.capability.clone())
            .collect()
    }
}

/// Unsatisfied capability information
#[derive(Debug, Clone)]
pub struct UnsatisfiedCapability {
    /// The unsatisfied capability
    pub capability: Capability,
    
    /// Reason why it's unsatisfied
    pub reason: String,
    
    /// Alternative capabilities
    pub alternatives: Vec<Capability>,
}

/// Builder for capability manager
pub struct CapabilityManagerBuilder {
    config: CapabilityConfig,
}

impl CapabilityManagerBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: CapabilityConfig::default(),
        }
    }
    
    /// Allow capability overrides
    pub fn allow_overrides(mut self, allow: bool) -> Self {
        self.config.allow_overrides = allow;
        self
    }
    
    /// Require semantic versioning
    pub fn require_semver(mut self, require: bool) -> Self {
        self.config.require_semver = require;
        self
    }
    
    /// Set maximum providers per capability
    pub fn max_providers(mut self, max: usize) -> Self {
        self.config.max_providers = max;
        self
    }
    
    /// Enable deprecation warnings
    pub fn deprecation_warnings(mut self, enable: bool) -> Self {
        self.config.deprecation_warnings = enable;
        self
    }
    
    /// Build the capability manager
    pub fn build(self) -> CapabilityManager {
        CapabilityManager::new(self.config)
    }
}

impl Default for CapabilityManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_capability_registration() {
        let manager = CapabilityManagerBuilder::new()
            .allow_overrides(false)
            .build();
        
        let def = CapabilityDefinition {
            capability: Capability::new("docker", "container.create", 1),
            description: "Create Docker containers".to_string(),
            methods: vec![],
            permissions: vec![],
            version: Version::new(1, 0, 0),
            deprecated: None,
            features: HashSet::new(),
        };
        
        manager.register_capability(def.clone()).await.unwrap();
        
        // Should fail on duplicate without overrides
        assert!(manager.register_capability(def).await.is_err());
    }
    
    #[tokio::test]
    async fn test_provider_registration() {
        let manager = CapabilityManager::new(CapabilityConfig::default());
        
        let capability = Capability::new("docker", "container.create", 1);
        
        manager.register_provider(
            "docker-plugin".to_string(),
            vec![capability.clone()],
        ).await.unwrap();
        
        let provider = manager.find_provider(&capability).await.unwrap();
        assert_eq!(provider, Some("docker-plugin".to_string()));
    }
}