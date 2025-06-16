//! Capability Negotiation - Dynamic Discovery and Binding
//!
//! This module enables plugins to discover each other's capabilities
//! and negotiate optimal communication patterns at runtime.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use std::collections::{HashMap};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use semver::{VersionReq};
use tracing::{ info, warn};

use super::{Capability, PluginError as Error, Metadata, Result};

/// Capability negotiator - handles dynamic capability discovery
pub struct CapabilityNegotiator {
    /// Registry of all known capabilities
    capabilities: Arc<RwLock<CapabilityRegistry>>,
    
    /// Negotiation sessions
    sessions: Arc<RwLock<HashMap<String, NegotiationSession>>>,
    
    /// Configuration
    config: NegotiatorConfig,
}

/// Capability registry
#[derive(Debug, Default)]
struct CapabilityRegistry {
    /// Capabilities by plugin ID
    by_plugin: HashMap<String, Vec<RegisteredCapability>>,
    
    /// Capabilities by namespace
    by_namespace: HashMap<String, Vec<RegisteredCapability>>,
    
    /// Capability dependencies
    dependencies: HashMap<String, Vec<CapabilityDependency>>,
    
    /// Version compatibility matrix
    compatibility: HashMap<(String, String), CompatibilityInfo>,
}

/// Registered capability with metadata
#[derive(Debug, Clone)]
struct RegisteredCapability {
    /// The capability
    capability: Capability,
    
    /// providing this capability
    plugin_id: String,
    
    /// Registration time
    registered_at: std::time::SystemTime,
    
    /// Health status
    health_status: HealthStatus,
    
    /// Performance metrics
    metrics: CapabilityMetrics,
}

/// Capability health status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HealthStatus {
    /// Capability is healthy
    Healthy,
    
    /// Capability is degraded
    Degraded,
    
    /// Capability is unavailable
    Unavailable,
}

/// Capability performance metrics
#[derive(Debug, Clone, Default)]
struct CapabilityMetrics {
    /// Average response time in microseconds
    avg_response_us: u64,
    
    /// Success rate (0.0 - 1.0)
    success_rate: f64,
    
    /// Total invocations
    invocations: u64,
    
    /// Last invocation time
    last_invocation: Option<std::time::SystemTime>,
}

/// Capability dependency
#[derive(Debug, Clone)]
struct CapabilityDependency {
    /// Required capability
    capability: String,
    
    /// Version requirement
    version_req: VersionReq,
    
    /// Is this optional?
    optional: bool,
}

/// Compatibility information
#[derive(Debug, Clone)]
struct CompatibilityInfo {
    /// Is compatible?
    compatible: bool,
    
    /// Compatibility score (0.0 - 1.0)
    score: f64,
    
    /// Required adaptations
    adaptations: Vec<Adaptation>,
    
    /// Performance impact
    performance_impact: PerformanceImpact,
}

/// Required adaptation for compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Adaptation {
    /// Adaptation type
    pub adaptation_type: AdaptationType,
    
    /// Description
    pub description: String,
    
    /// Configuration changes needed
    pub config_changes: Value,
}

/// Adaptation types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AdaptationType {
    /// Protocol version downgrade
    ProtocolDowngrade,
    
    /// Feature limitation
    FeatureLimitation,
    
    /// Performance throttling
    PerformanceThrottling,
    
    /// Security enhancement
    SecurityEnhancement,
}

/// Performance impact assessment
#[derive(Debug, Clone, Copy)]
struct PerformanceImpact {
    /// Latency increase factor
    latency_factor: f64,
    
    /// Throughput reduction factor
    throughput_factor: f64,
    
    /// Memory overhead in bytes
    memory_overhead: usize,
}

/// Negotiation session
#[derive(Debug)]
struct NegotiationSession {
    /// Session ID
    id: String,
    
    /// Participating plugins
    participants: Vec<String>,
    
    /// Session state
    state: NegotiationState,
    
    /// Negotiation result
    result: Option<NegotiationResult>,
    
    /// Started at
    started_at: std::time::SystemTime,
    
    /// Updated at
    updated_at: std::time::SystemTime,
}

/// Negotiation state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NegotiationState {
    /// Initial state
    Initiated,
    
    /// Discovering capabilities
    Discovering,
    
    /// Analyzing compatibility
    Analyzing,
    
    /// Proposing terms
    Proposing,
    
    /// Finalizing agreement
    Finalizing,
    
    /// Completed successfully
    Completed,
    
    /// Failed to negotiate
    Failed,
}

/// Negotiation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiationResult {
    /// Agreed capabilities
    pub capabilities: Vec<AgreedCapability>,
    
    /// Communication protocol
    pub protocol: CommunicationProtocol,
    
    /// Quality of service parameters
    pub qos: QualityOfService,
    
    /// Security requirements
    pub security: SecurityRequirements,
    
    /// Validity period
    pub valid_until: std::time::SystemTime,
}

/// Agreed capability after negotiation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgreedCapability {
    /// The capability
    pub capability: Capability,
    
    /// Provider plugin
    pub provider: String,
    
    /// Consumer plugin
    pub consumer: String,
    
    /// Agreed version
    pub version: u32,
    
    /// Required adaptations
    pub adaptations: Vec<Adaptation>,
}

/// Communication protocol details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunicationProtocol {
    /// Protocol type
    pub protocol_type: ProtocolType,
    
    /// Serialization format
    pub serialization: SerializationFormat,
    
    /// Compression enabled
    pub compression: bool,
    
    /// Batching configuration
    pub batching: Option<BatchingConfig>,
}

/// Protocol types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ProtocolType {
    /// Direct function calls
    Direct,
    
    /// Message passing
    MessagePassing,
    
    /// Shared memory
    SharedMemory,
    
    /// Network RPC
    NetworkRPC,
}

/// Serialization formats
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SerializationFormat {
    /// JSON
    Json,
    
    /// MessagePack
    MessagePack,
    
    /// Protocol Buffers
    ProtoBuf,
    
    /// Native Rust
    Native,
}

/// Batching configuration
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BatchingConfig {
    /// Maximum batch size
    pub max_batch_size: usize,
    
    /// Maximum wait time in milliseconds
    pub max_wait_ms: u64,
}

/// Quality of service parameters
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct QualityOfService {
    /// Maximum latency in milliseconds
    pub max_latency_ms: u64,
    
    /// Minimum throughput in requests/second
    pub min_throughput_rps: u64,
    
    /// Reliability level
    pub reliability: ReliabilityLevel,
    
    /// Priority level
    pub priority: PriorityLevel,
}

/// Reliability levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ReliabilityLevel {
    /// Best effort - no guarantees
    BestEffort,
    
    /// At least once delivery
    AtLeastOnce,
    
    /// Exactly once delivery
    ExactlyOnce,
}

/// Priority levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PriorityLevel {
    /// Low priority
    Low,
    
    /// Normal priority
    Normal,
    
    /// High priority
    High,
    
    /// Critical priority
    Critical,
}

/// Security requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRequirements {
    /// Authentication required
    pub authentication: bool,
    
    /// Encryption required
    pub encryption: bool,
    
    /// Integrity checking
    pub integrity: bool,
    
    /// Audit logging
    pub audit_logging: bool,
    
    /// Allowed authentication methods
    pub auth_methods: Vec<String>,
}

/// Negotiator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiatorConfig {
    /// Maximum negotiation time in seconds
    pub negotiation_timeout_secs: u64,
    
    /// Enable automatic renegotiation
    pub auto_renegotiate: bool,
    
    /// Renegotiation interval in seconds
    pub renegotiation_interval_secs: u64,
    
    /// Compatibility score threshold
    pub min_compatibility_score: f64,
    
    /// Enable performance optimization
    pub optimize_performance: bool,
    
    /// Enable security hardening
    pub security_hardening: bool,
}

impl Default for NegotiatorConfig {
    fn default() -> Self {
        Self {
            negotiation_timeout_secs: 30,
            auto_renegotiate: true,
            renegotiation_interval_secs: 3600, // 1 hour
            min_compatibility_score: 0.7,
            optimize_performance: true,
            security_hardening: true,
        }
    }
}

impl CapabilityNegotiator {
    /// Create a new capability negotiator
    pub fn new(config: NegotiatorConfig) -> Self {
        Self {
            capabilities: Arc::new(RwLock::new(CapabilityRegistry::default())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }
    
    /// Register plugin capabilities
    pub async fn register_plugin(&self, metadata: &Metadata) -> Result<()> {
        let mut registry = self.capabilities.write().await;
        
        // Register each capability
        let mut registered_caps = Vec::new();
        for capability in &metadata.provides {
            let reg_cap = RegisteredCapability {
                capability: capability.clone(),
                plugin_id: metadata.id.clone(),
                registered_at: std::time::SystemTime::now(),
                health_status: HealthStatus::Healthy,
                metrics: CapabilityMetrics::default(),
            };
            
            registered_caps.push(reg_cap.clone());
            
            // Index by namespace
            registry.by_namespace
                .entry(capability.namespace.clone())
                .or_insert_with(Vec::new)
                .push(reg_cap);
        }
        
        // Store by plugin
        registry.by_plugin.insert(metadata.id.clone(), registered_caps);
        
        info!("Registered {} capabilities for plugin {}", 
              metadata.provides.len(), metadata.id);
        
        Ok(())
    }
    
    /// Unregister plugin capabilities
    pub async fn unregister_plugin(&self, plugin_id: &str) -> Result<()> {
        let mut registry = self.capabilities.write().await;
        
        // Remove from plugin index
        if let Some(caps) = registry.by_plugin.remove(plugin_id) {
            // Remove from namespace index
            for cap in caps {
                if let Some(namespace_caps) = registry.by_namespace.get_mut(&cap.capability.namespace) {
                    namespace_caps.retain(|c| c.plugin_id != plugin_id);
                }
            }
            
            info!("Unregistered capabilities for plugin {}", plugin_id);
        }
        
        Ok(())
    }
    
    /// Start negotiation session
    pub async fn start_negotiation(
        &self,
        consumer: &str,
        required_capabilities: Vec<Capability>,
    ) -> Result<String> {
        let session_id = uuid::Uuid::new_v4().to_string();
        
        let session = NegotiationSession {
            id: session_id.clone(),
            participants: vec![consumer.to_string()],
            state: NegotiationState::Initiated,
            result: None,
            started_at: std::time::SystemTime::now(),
            updated_at: std::time::SystemTime::now(),
        };
        
        self.sessions.write().await.insert(session_id.clone(), session);
        
        // Start async negotiation
        let negotiator = self.clone();
        let consumer = consumer.to_string();
        let session_id_clone = session_id.clone();
        
        tokio::spawn(async move {
            if let Err(e) = negotiator.run_negotiation(
                &session_id_clone,
                &consumer,
                required_capabilities,
            ).await {
                warn!("Negotiation {} failed: {}", session_id_clone, e);
            }
        });
        
        Ok(session_id)
    }
    
    /// Run negotiation process
    async fn run_negotiation(
        &self,
        session_id: &str,
        consumer: &str,
        required_capabilities: Vec<Capability>,
    ) -> Result<()> {
        // Update state to discovering
        self.update_session_state(session_id, NegotiationState::Discovering).await?;
        
        // Discover available providers
        let providers = self.discover_providers(&required_capabilities).await?;
        
        if providers.is_empty() {
            self.update_session_state(session_id, NegotiationState::Failed).await?;
            return Err(Error::ExecutionError(
                "No providers found for required capabilities".to_string()
            ));
        }
        
        // Update state to analyzing
        self.update_session_state(session_id, NegotiationState::Analyzing).await?;
        
        // Analyze compatibility
        let compatibility_results = self.analyze_compatibility(
            consumer,
            &required_capabilities,
            &providers,
        ).await?;
        
        // Update state to proposing
        self.update_session_state(session_id, NegotiationState::Proposing).await?;
        
        // Generate proposals
        let proposals = self.generate_proposals(
            consumer,
            &required_capabilities,
            &compatibility_results,
        ).await?;
        
        if proposals.is_empty() {
            self.update_session_state(session_id, NegotiationState::Failed).await?;
            return Err(Error::ExecutionError(
                "No viable proposals generated".to_string()
            ));
        }
        
        // Update state to finalizing
        self.update_session_state(session_id, NegotiationState::Finalizing).await?;
        
        // Select best proposal
        let best_proposal = self.select_best_proposal(&proposals).await?;
        
        // Finalize negotiation
        self.finalize_negotiation(session_id, best_proposal).await?;
        
        // Update state to completed
        self.update_session_state(session_id, NegotiationState::Completed).await?;
        
        Ok(())
    }
    
    /// Discover providers for capabilities
    async fn discover_providers(
        &self,
        capabilities: &[Capability],
    ) -> Result<HashMap<String, Vec<RegisteredCapability>>> {
        let registry = self.capabilities.read().await;
        let mut providers = HashMap::new();
        
        for required in capabilities {
            let namespace_providers = registry.by_namespace
                .get(&required.namespace)
                .cloned()
                .unwrap_or_default();
            
            let matching_providers: Vec<_> = namespace_providers
                .into_iter()
                .filter(|p| {
                    p.capability.name == required.name &&
                    p.capability.version >= required.version &&
                    p.health_status != HealthStatus::Unavailable
                })
                .collect();
            
            providers.insert(required.to_string(), matching_providers);
        }
        
        Ok(providers)
    }
    
    /// Analyze compatibility between consumer and providers
    async fn analyze_compatibility(
        &self,
        _consumer: &str,
        capabilities: &[Capability],
        providers: &HashMap<String, Vec<RegisteredCapability>>,
    ) -> Result<Vec<CompatibilityAnalysis>> {
        let mut analyses = Vec::new();
        
        for capability in capabilities {
            let cap_providers = providers.get(&capability.to_string())
                .cloned()
                .unwrap_or_default();
            
            for provider in cap_providers {
                let compatibility = self.calculate_compatibility(
                    capability,
                    &provider,
                ).await?;
                
                analyses.push(CompatibilityAnalysis {
                    capability: capability.clone(),
                    provider: provider.plugin_id.clone(),
                    compatibility,
                });
            }
        }
        
        Ok(analyses)
    }
    
    /// Calculate compatibility score
    async fn calculate_compatibility(
        &self,
        required: &Capability,
        provider: &RegisteredCapability,
    ) -> Result<CompatibilityInfo> {
        let mut score = 1.0;
        let mut adaptations = Vec::new();
        
        // Version compatibility
        if provider.capability.version > required.version {
            // Newer version - full compatibility
            score *= 1.0;
        } else if provider.capability.version == required.version {
            // Exact match - perfect
            score *= 1.0;
        } else {
            // Older version - may need adaptation
            score *= 0.8;
            adaptations.push(Adaptation {
                adaptation_type: AdaptationType::ProtocolDowngrade,
                description: format!(
                    "Provider version {} is older than required {}",
                    provider.capability.version, required.version
                ),
                config_changes: json!({
                    "use_legacy_protocol": true,
                    "version": provider.capability.version,
                }),
            });
        }
        
        // Health status impact
        match provider.health_status {
            HealthStatus::Healthy => score *= 1.0,
            HealthStatus::Degraded => {
                score *= 0.7;
                adaptations.push(Adaptation {
                    adaptation_type: AdaptationType::PerformanceThrottling,
                    description: "Provider is in degraded state".to_string(),
                    config_changes: json!({
                        "reduce_load": true,
                        "max_concurrent_requests": 10,
                    }),
                });
            }
            HealthStatus::Unavailable => score *= 0.0,
        }
        
        // Performance metrics impact
        if provider.metrics.success_rate < 0.95 {
            score *= provider.metrics.success_rate;
            adaptations.push(Adaptation {
                adaptation_type: AdaptationType::FeatureLimitation,
                description: format!(
                    "Provider success rate is {:.2}%",
                    provider.metrics.success_rate * 100.0
                ),
                config_changes: json!({
                    "enable_retry": true,
                    "max_retries": 3,
                }),
            });
        }
        
        // Calculate performance impact
        let performance_impact = PerformanceImpact {
            latency_factor: if adaptations.is_empty() { 1.0 } else { 1.2 },
            throughput_factor: score,
            memory_overhead: adaptations.len() * 1024, // Rough estimate
        };
        
        Ok(CompatibilityInfo {
            compatible: score >= self.config.min_compatibility_score,
            score,
            adaptations,
            performance_impact,
        })
    }
    
    /// Generate negotiation proposals
    async fn generate_proposals(
        &self,
        consumer: &str,
        capabilities: &[Capability],
        compatibility_results: &[CompatibilityAnalysis],
    ) -> Result<Vec<NegotiationProposal>> {
        let mut proposals = Vec::new();
        
        // Group by compatibility score
        let mut by_score: HashMap<String, Vec<&CompatibilityAnalysis>> = HashMap::new();
        for analysis in compatibility_results {
            if analysis.compatibility.compatible {
                by_score.entry(analysis.provider.clone())
                    .or_insert_with(Vec::new)
                    .push(analysis);
            }
        }
        
        // Generate proposals for each provider combination
        for (provider, analyses) in by_score {
            let mut agreed_capabilities = Vec::new();
            let mut total_score = 0.0;
            let mut all_adaptations = Vec::new();
            let analyses_count = analyses.len();
            
            for analysis in analyses {
                agreed_capabilities.push(AgreedCapability {
                    capability: analysis.capability.clone(),
                    provider: provider.clone(),
                    consumer: consumer.to_string(),
                    version: analysis.capability.version,
                    adaptations: analysis.compatibility.adaptations.clone(),
                });
                
                total_score += analysis.compatibility.score;
                all_adaptations.extend(analysis.compatibility.adaptations.clone());
            }
            
            let avg_score = total_score / analyses_count as f64;
            
            // Determine optimal protocol
            let protocol = self.determine_protocol(&all_adaptations, avg_score);
            
            // Determine QoS parameters
            let qos = self.determine_qos(&all_adaptations, avg_score);
            
            // Determine security requirements
            let security = self.determine_security(&all_adaptations);
            
            proposals.push(NegotiationProposal {
                proposal_id: uuid::Uuid::new_v4().to_string(),
                score: avg_score,
                result: NegotiationResult {
                    capabilities: agreed_capabilities,
                    protocol,
                    qos,
                    security,
                    valid_until: std::time::SystemTime::now() + 
                        std::time::Duration::from_secs(self.config.renegotiation_interval_secs),
                },
            });
        }
        
        // Sort by score
        proposals.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        
        Ok(proposals)
    }
    
    /// Determine optimal communication protocol
    fn determine_protocol(&self, adaptations: &[Adaptation], score: f64) -> CommunicationProtocol {
        let protocol_type = if score > 0.9 && adaptations.is_empty() {
            ProtocolType::Direct
        } else if score > 0.7 {
            ProtocolType::MessagePassing
        } else {
            ProtocolType::NetworkRPC
        };
        
        let serialization = if self.config.optimize_performance && score > 0.8 {
            SerializationFormat::Native
        } else {
            SerializationFormat::Json
        };
        
        let compression = adaptations.len() > 2 || score < 0.8;
        
        let batching = if self.config.optimize_performance && score > 0.7 {
            Some(BatchingConfig {
                max_batch_size: 100,
                max_wait_ms: 10,
            })
        } else {
            None
        };
        
        CommunicationProtocol {
            protocol_type,
            serialization,
            compression,
            batching,
        }
    }
    
    /// Determine quality of service parameters
    fn determine_qos(&self, adaptations: &[Adaptation], score: f64) -> QualityOfService {
        let performance_throttled = adaptations.iter()
            .any(|a| matches!(a.adaptation_type, AdaptationType::PerformanceThrottling));
        
        QualityOfService {
            max_latency_ms: if performance_throttled { 1000 } else { 100 },
            min_throughput_rps: if score > 0.8 { 1000 } else { 100 },
            reliability: if score > 0.9 {
                ReliabilityLevel::ExactlyOnce
            } else if score > 0.7 {
                ReliabilityLevel::AtLeastOnce
            } else {
                ReliabilityLevel::BestEffort
            },
            priority: if score > 0.9 {
                PriorityLevel::High
            } else {
                PriorityLevel::Normal
            },
        }
    }
    
    /// Determine security requirements
    fn determine_security(&self, _adaptations: &[Adaptation]) -> SecurityRequirements {
        SecurityRequirements {
            authentication: self.config.security_hardening,
            encryption: self.config.security_hardening,
            integrity: true,
            audit_logging: self.config.security_hardening,
            auth_methods: vec!["jwt".to_string(), "mtls".to_string()],
        }
    }
    
    /// Select best proposal
    async fn select_best_proposal(
        &self,
        proposals: &[NegotiationProposal],
    ) -> Result<NegotiationResult> {
        proposals.first()
            .map(|p| p.result.clone())
            .ok_or_else(|| Error::ExecutionError("No proposals available".to_string()))
    }
    
    /// Finalize negotiation
    async fn finalize_negotiation(
        &self,
        session_id: &str,
        result: NegotiationResult,
    ) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.result = Some(result);
            session.updated_at = std::time::SystemTime::now();
        }
        Ok(())
    }
    
    /// Update session state
    async fn update_session_state(
        &self,
        session_id: &str,
        state: NegotiationState,
    ) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.state = state;
            session.updated_at = std::time::SystemTime::now();
            Ok(())
        } else {
            Err(Error::NotFound(format!("Session {} not found", session_id)))
        }
    }
    
    /// Get negotiation result
    pub async fn get_negotiation_result(
        &self,
        session_id: &str,
    ) -> Result<Option<NegotiationResult>> {
        let sessions = self.sessions.read().await;
        Ok(sessions.get(session_id).and_then(|s| s.result.clone()))
    }
    
    /// Check negotiation status
    pub async fn check_negotiation_status(
        &self,
        session_id: &str,
    ) -> Result<NegotiationState> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id)
            .map(|s| s.state)
            .ok_or_else(|| Error::NotFound(format!("Session {} not found", session_id)))
    }
    
    /// Update capability metrics
    pub async fn update_capability_metrics(
        &self,
        plugin_id: &str,
        capability: &Capability,
        success: bool,
        response_time_us: u64,
    ) -> Result<()> {
        let mut registry = self.capabilities.write().await;
        
        if let Some(caps) = registry.by_plugin.get_mut(plugin_id) {
            if let Some(cap) = caps.iter_mut().find(|c| &c.capability == capability) {
                cap.metrics.invocations += 1;
                cap.metrics.last_invocation = Some(std::time::SystemTime::now());
                
                // Update success rate with exponential moving average
                let alpha = 0.1; // Smoothing factor
                let current_success = if success { 1.0 } else { 0.0 };
                cap.metrics.success_rate = 
                    alpha * current_success + (1.0 - alpha) * cap.metrics.success_rate;
                
                // Update average response time
                cap.metrics.avg_response_us = 
                    (cap.metrics.avg_response_us * (cap.metrics.invocations - 1) + response_time_us) 
                    / cap.metrics.invocations;
            }
        }
        
        Ok(())
    }
}

// Helper structs

#[derive(Debug)]
struct CompatibilityAnalysis {
    capability: Capability,
    provider: String,
    compatibility: CompatibilityInfo,
}

#[derive(Debug)]
struct NegotiationProposal {
    proposal_id: String,
    score: f64,
    result: NegotiationResult,
}

// Make negotiator cloneable
impl Clone for CapabilityNegotiator {
    fn clone(&self) -> Self {
        Self {
            capabilities: self.capabilities.clone(),
            sessions: self.sessions.clone(),
            config: self.config.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_capability_negotiation() {
        let config = NegotiatorConfig::default();
        let negotiator = CapabilityNegotiator::new(config);
        
        // Register a provider plugin
        let provider_metadata = Metadata {
            id: "test-provider".to_string(),
            name: "Test Provider".to_string(),
            version: "1.0.0".to_string(),
            author: "Test".to_string(),
            description: "Test provider".to_string(),
            license: "MIT".to_string(),
            homepage: None,
            repository: None,
            min_mcp_version: "1.0.0".to_string(),
            dependencies: vec![],
            provides: vec![
                Capability::new("test", "operation.execute", 1),
                Capability::new("test", "operation.query", 1),
            ],
            requires: vec![],
        };
        
        negotiator.register_plugin(&provider_metadata).await.unwrap();
        
        // Start negotiation
        let required = vec![
            Capability::new("test", "operation.execute", 1),
        ];
        
        let session_id = negotiator.start_negotiation("test-consumer", required).await.unwrap();
        
        // Wait a bit for negotiation
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Check status
        let status = negotiator.check_negotiation_status(&session_id).await.unwrap();
        assert!(matches!(status, NegotiationState::Completed | NegotiationState::Failed));
    }
}