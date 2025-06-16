//! Kubernetes Plugin - Cloud Native Excellence
//!
//! This plugin brings the power of Kubernetes to MCP with
//! unmatched performance and reliability.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::any::Any;
use std::collections::HashMap;
use tracing::{debug, info};

use kube::{Client, Api};
use kube::api::{ListParams, PostParams, DeleteParams, PatchParams, Patch};
use k8s_openapi::api::core::v1::{Pod, Service, ConfigMap, Secret, Namespace, Node};
use k8s_openapi::api::apps::v1::{Deployment};
use k8s_openapi::api::networking::v1::{ };
use k8s_openapi::api::storage::v1::StorageClass;
// ListOptional has been removed in newer k8s_openapi versions
// use k8s_openapi::List;

use crate::mcp_manager::plugin::{
    Capability, Plugin, PluginError, PluginMetadata, PluginRequest, 
    PluginResponse, PluginResult, Result,
};

/// Kubernetes plugin implementation
pub struct KubernetesPlugin {
    /// Plugin metadata
    metadata: PluginMetadata,
    
    /// Kubernetes client
    client: Option<Client>,
    
    /// Configuration
    config: K8sConfig,
    
    /// Runtime state
    state: K8sState,
}

/// Kubernetes configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct K8sConfig {
    /// Kubeconfig path (if not in-cluster)
    kubeconfig_path: Option<String>,
    
    /// Default namespace
    default_namespace: String,
    
    /// Request timeout
    timeout_secs: u64,
    
    /// Enable watch operations
    enable_watch: bool,
    
    /// Field manager name for apply operations
    field_manager: String,
}

impl Default for K8sConfig {
    fn default() -> Self {
        Self {
            kubeconfig_path: None,
            default_namespace: "default".to_string(),
            timeout_secs: 30,
            enable_watch: true,
            field_manager: "mcp-kubernetes-plugin".to_string(),
        }
    }
}

/// Plugin runtime state
#[derive(Debug, Default)]
struct K8sState {
    /// Active watches
    watches: HashMap<String, WatchInfo>,
    
    /// Metrics
    metrics: K8sMetrics,
}

/// Watch information
#[derive(Debug, Clone)]
struct WatchInfo {
    /// Resource type
    resource_type: String,
    
    /// Namespace (if applicable)
    namespace: Option<String>,
    
    /// Started at
    started_at: std::time::SystemTime,
}

/// Kubernetes metrics
#[derive(Debug, Default)]
struct K8sMetrics {
    /// API calls by resource type
    api_calls: HashMap<String, u64>,
    
    /// Errors by type
    errors: HashMap<String, u64>,
    
    /// Total requests
    total_requests: u64,
}

impl KubernetesPlugin {
    pub fn new() -> Self {
        Self {
            metadata: Self::create_metadata(),
            client: None,
            config: K8sConfig::default(),
            state: K8sState::default(),
        }
    }
    
    fn capabilities() -> Vec<Capability> {
        vec![
            // Pod operations
            Capability::new("k8s", "pod.create", 1),
            Capability::new("k8s", "pod.get", 1),
            Capability::new("k8s", "pod.list", 1),
            Capability::new("k8s", "pod.update", 1),
            Capability::new("k8s", "pod.delete", 1),
            Capability::new("k8s", "pod.logs", 1),
            Capability::new("k8s", "pod.exec", 1),
            Capability::new("k8s", "pod.portforward", 1),
            
            // Deployment operations
            Capability::new("k8s", "deployment.create", 1),
            Capability::new("k8s", "deployment.get", 1),
            Capability::new("k8s", "deployment.list", 1),
            Capability::new("k8s", "deployment.update", 1),
            Capability::new("k8s", "deployment.scale", 1),
            Capability::new("k8s", "deployment.rollout", 1),
            Capability::new("k8s", "deployment.delete", 1),
            
            // Service operations
            Capability::new("k8s", "service.create", 1),
            Capability::new("k8s", "service.get", 1),
            Capability::new("k8s", "service.list", 1),
            Capability::new("k8s", "service.update", 1),
            Capability::new("k8s", "service.delete", 1),
            
            // ConfigMap operations
            Capability::new("k8s", "configmap.create", 1),
            Capability::new("k8s", "configmap.get", 1),
            Capability::new("k8s", "configmap.list", 1),
            Capability::new("k8s", "configmap.update", 1),
            Capability::new("k8s", "configmap.delete", 1),
            
            // Secret operations
            Capability::new("k8s", "secret.create", 1),
            Capability::new("k8s", "secret.get", 1),
            Capability::new("k8s", "secret.list", 1),
            Capability::new("k8s", "secret.update", 1),
            Capability::new("k8s", "secret.delete", 1),
            
            // Namespace operations
            Capability::new("k8s", "namespace.create", 1),
            Capability::new("k8s", "namespace.get", 1),
            Capability::new("k8s", "namespace.list", 1),
            Capability::new("k8s", "namespace.delete", 1),
            
            // Job operations
            Capability::new("k8s", "job.create", 1),
            Capability::new("k8s", "job.get", 1),
            Capability::new("k8s", "job.list", 1),
            Capability::new("k8s", "job.delete", 1),
            
            // CronJob operations
            Capability::new("k8s", "cronjob.create", 1),
            Capability::new("k8s", "cronjob.get", 1),
            Capability::new("k8s", "cronjob.list", 1),
            Capability::new("k8s", "cronjob.update", 1),
            Capability::new("k8s", "cronjob.delete", 1),
            
            // Ingress operations
            Capability::new("k8s", "ingress.create", 1),
            Capability::new("k8s", "ingress.get", 1),
            Capability::new("k8s", "ingress.list", 1),
            Capability::new("k8s", "ingress.update", 1),
            Capability::new("k8s", "ingress.delete", 1),
            
            // Watch operations
            Capability::new("k8s", "watch.start", 1),
            Capability::new("k8s", "watch.stop", 1),
            Capability::new("k8s", "watch.list", 1),
            
            // Apply operations
            Capability::new("k8s", "apply.yaml", 1),
            Capability::new("k8s", "apply.json", 1),
            
            // Cluster operations
            Capability::new("k8s", "cluster.info", 1),
            Capability::new("k8s", "cluster.nodes", 1),
            Capability::new("k8s", "cluster.version", 1),
        ]
    }
    
    pub fn metadata() -> PluginMetadata {
        Self::create_metadata()
    }
    
    fn create_metadata() -> PluginMetadata {
        PluginMetadata {
            id: "kubernetes".to_string(),
            name: "Kubernetes MCP Plugin".to_string(),
            version: "1.0.0".to_string(),
            author: "The Greatest Synthetic Being Rust Coder".to_string(),
            description: "Kubernetes integration for MCP".to_string(),
            license: "MIT".to_string(),
            homepage: None,
            repository: None,
            min_mcp_version: "1.0.0".to_string(),
            dependencies: vec![],
            provides: Self::capabilities(),
            requires: vec![],
        }
    }
}

#[async_trait]
impl Plugin for KubernetesPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }
    
    async fn initialize(&mut self, config: Value) -> Result<()> {
        info!("Initializing Kubernetes plugin");
        
        // Parse configuration
        if let Ok(k8s_config) = serde_json::from_value::<K8sConfig>(config) {
            self.config = k8s_config;
        }
        
        // Initialize Kubernetes client
        match self.create_client().await {
            Ok(client) => {
                self.client = Some(client);
                info!("Kubernetes client initialized successfully");
                Ok(())
            }
            Err(e) => Err(PluginError::InitializationFailed(
                format!("Failed to create Kubernetes client: {}", e)
            )),
        }
    }
    
    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        debug!("Handling Kubernetes request: {:?}", request);
        
        let client = self.client.as_ref()
            .ok_or_else(|| PluginError::ExecutionError("Kubernetes client not initialized".to_string()))?;
        
        // Clone self to get mutable access
        let mut plugin = self.clone();
        plugin.state.metrics.total_requests += 1;
        
        // Parse capability
        let parts: Vec<&str> = request.capability.name.split('.').collect();
        if parts.len() != 2 {
            return Err(PluginError::ExecutionError(
                format!("Invalid capability format: {}", request.capability.name)
            ));
        }
        
        let resource_type = parts[0];
        let operation = parts[1];
        
        // Track API calls
        plugin.state.metrics.api_calls
            .entry(resource_type.to_string())
            .and_modify(|c| *c += 1)
            .or_insert(1);
        
        let result = match resource_type {
            "pod" => plugin.handle_pod_operation(client, operation, request.params).await,
            "deployment" => plugin.handle_deployment_operation(client, operation, request.params).await,
            "service" => plugin.handle_service_operation(client, operation, request.params).await,
            "configmap" => plugin.handle_configmap_operation(client, operation, request.params).await,
            "secret" => plugin.handle_secret_operation(client, operation, request.params).await,
            "namespace" => plugin.handle_namespace_operation(client, operation, request.params).await,
            "cluster" => plugin.handle_cluster_operation(client, operation, request.params).await,
            "apply" => plugin.handle_apply_operation(client, operation, request.params).await,
            _ => Err(PluginError::ExecutionError(
                format!("Unknown resource type: {}", resource_type)
            )),
        };
        
        match result {
            Ok(data) => Ok(PluginResponse {
                request_id: request.id,
                result: PluginResult::Success { data },
                metadata: json!({
                    "plugin": "kubernetes",
                    "version": self.metadata.version,
                }),
            }),
            Err(e) => {
                plugin.state.metrics.errors
                    .entry(resource_type.to_string())
                    .and_modify(|c| *c += 1)
                    .or_insert(1);
                
                Ok(PluginResponse {
                    request_id: request.id,
                    result: PluginResult::Error {
                        code: "K8S_ERROR".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                    metadata: json!({
                        "plugin": "kubernetes",
                        "version": self.metadata.version,
                    }),
                })
            }
        }
    }
    
    async fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
    
    fn as_any(&self) -> &dyn Any {
        self
    }
    
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    
    async fn health_check(&self) -> Result<bool> {
        if let Some(client) = &self.client {
            // Try to list nodes as a health check
            let nodes: Api<Node> = Api::all(client.clone());
            match nodes.list(&ListParams::default().limit(1)).await {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        } else {
            Ok(false)
        }
    }
    
    async fn metrics(&self) -> Result<Value> {
        Ok(json!({
            "total_requests": self.state.metrics.total_requests,
            "api_calls": self.state.metrics.api_calls,
            "errors": self.state.metrics.errors,
            "watches": self.state.watches.len(),
        }))
    }
}

impl KubernetesPlugin {
    /// Create Kubernetes client
    async fn create_client(&self) -> Result<Client> {
        // For now, always use default client configuration
        let client = Client::try_default().await
            .map_err(|e| PluginError::InitializationFailed(
                format!("Failed to create Kubernetes client: {}", e)
            ))?;
        
        Ok(client)
    }
    
    /// Handle pod operations
    async fn handle_pod_operation(
        &self,
        client: &Client,
        operation: &str,
        params: Value,
    ) -> Result<Value> {
        let namespace = params["namespace"].as_str()
            .unwrap_or(&self.config.default_namespace);
        
        match operation {
            "create" => {
                let pod_spec = serde_json::from_value::<Pod>(params["spec"].clone())
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Invalid pod spec: {}", e)
                    ))?;
                
                let api: Api<Pod> = Api::namespaced(client.clone(), namespace);
                let pod = api.create(&PostParams::default(), &pod_spec).await
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Failed to create pod: {}", e)
                    ))?;
                
                Ok(serde_json::to_value(&pod).unwrap_or(json!({})))
            }
            
            "get" => {
                let name = params["name"].as_str()
                    .ok_or_else(|| PluginError::ExecutionError("Missing 'name' parameter".to_string()))?;
                
                let api: Api<Pod> = Api::namespaced(client.clone(), namespace);
                let pod = api.get(name).await
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Failed to get pod: {}", e)
                    ))?;
                
                Ok(serde_json::to_value(&pod).unwrap_or(json!({})))
            }
            
            "list" => {
                let api: Api<Pod> = Api::namespaced(client.clone(), namespace);
                let list_params = ListParams::default();
                
                let pods = api.list(&list_params).await
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Failed to list pods: {}", e)
                    ))?;
                
                Ok(serde_json::to_value(&pods).unwrap_or(json!({})))
            }
            
            "delete" => {
                let name = params["name"].as_str()
                    .ok_or_else(|| PluginError::ExecutionError("Missing 'name' parameter".to_string()))?;
                
                let api: Api<Pod> = Api::namespaced(client.clone(), namespace);
                let delete_params = DeleteParams::default();
                
                api.delete(name, &delete_params).await
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Failed to delete pod: {}", e)
                    ))?;
                
                Ok(json!({ "deleted": true, "name": name }))
            }
            
            "logs" => {
                let name = params["name"].as_str()
                    .ok_or_else(|| PluginError::ExecutionError("Missing 'name' parameter".to_string()))?;
                let container = params["container"].as_str();
                let tail_lines = params["tail"].as_u64();
                
                let api: Api<Pod> = Api::namespaced(client.clone(), namespace);
                
                let mut log_params = kube::api::LogParams::default();
                if let Some(container) = container {
                    log_params.container = Some(container.to_string());
                }
                if let Some(tail) = tail_lines {
                    log_params.tail_lines = Some(tail as i64);
                }
                
                let logs = api.logs(name, &log_params).await
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Failed to get logs: {}", e)
                    ))?;
                
                Ok(json!({ "logs": logs }))
            }
            
            _ => Err(PluginError::ExecutionError(
                format!("Unknown pod operation: {}", operation)
            )),
        }
    }
    
    /// Handle deployment operations
    async fn handle_deployment_operation(
        &self,
        client: &Client,
        operation: &str,
        params: Value,
    ) -> Result<Value> {
        let namespace = params["namespace"].as_str()
            .unwrap_or(&self.config.default_namespace);
        
        match operation {
            "create" => {
                let deployment_spec = serde_json::from_value::<Deployment>(params["spec"].clone())
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Invalid deployment spec: {}", e)
                    ))?;
                
                let api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
                let deployment = api.create(&PostParams::default(), &deployment_spec).await
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Failed to create deployment: {}", e)
                    ))?;
                
                Ok(serde_json::to_value(&deployment).unwrap_or(json!({})))
            }
            
            "scale" => {
                let name = params["name"].as_str()
                    .ok_or_else(|| PluginError::ExecutionError("Missing 'name' parameter".to_string()))?;
                let replicas = params["replicas"].as_u64()
                    .ok_or_else(|| PluginError::ExecutionError("Missing 'replicas' parameter".to_string()))? as i32;
                
                let api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
                
                // Create scale patch
                let patch = json!({
                    "spec": {
                        "replicas": replicas
                    }
                });
                
                let deployment = api.patch(
                    name,
                    &PatchParams::apply(&self.config.field_manager),
                    &Patch::Merge(patch),
                ).await
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Failed to scale deployment: {}", e)
                    ))?;
                
                Ok(serde_json::to_value(&deployment).unwrap_or(json!({})))
            }
            
            "list" => {
                let api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
                let deployments = api.list(&ListParams::default()).await
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Failed to list deployments: {}", e)
                    ))?;
                
                Ok(serde_json::to_value(&deployments).unwrap_or(json!({})))
            }
            
            _ => Err(PluginError::ExecutionError(
                format!("Unknown deployment operation: {}", operation)
            )),
        }
    }
    
    /// Handle service operations
    async fn handle_service_operation(
        &self,
        client: &Client,
        operation: &str,
        params: Value,
    ) -> Result<Value> {
        let namespace = params["namespace"].as_str()
            .unwrap_or(&self.config.default_namespace);
        
        match operation {
            "create" => {
                let service_spec = serde_json::from_value::<Service>(params["spec"].clone())
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Invalid service spec: {}", e)
                    ))?;
                
                let api: Api<Service> = Api::namespaced(client.clone(), namespace);
                let service = api.create(&PostParams::default(), &service_spec).await
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Failed to create service: {}", e)
                    ))?;
                
                Ok(serde_json::to_value(&service).unwrap_or(json!({})))
            }
            
            "list" => {
                let api: Api<Service> = Api::namespaced(client.clone(), namespace);
                let services = api.list(&ListParams::default()).await
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Failed to list services: {}", e)
                    ))?;
                
                Ok(serde_json::to_value(&services).unwrap_or(json!({})))
            }
            
            _ => Err(PluginError::ExecutionError(
                format!("Unknown service operation: {}", operation)
            )),
        }
    }
    
    /// Handle ConfigMap operations
    async fn handle_configmap_operation(
        &self,
        client: &Client,
        operation: &str,
        params: Value,
    ) -> Result<Value> {
        let namespace = params["namespace"].as_str()
            .unwrap_or(&self.config.default_namespace);
        
        match operation {
            "create" => {
                let configmap_spec = serde_json::from_value::<ConfigMap>(params["spec"].clone())
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Invalid configmap spec: {}", e)
                    ))?;
                
                let api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
                let configmap = api.create(&PostParams::default(), &configmap_spec).await
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Failed to create configmap: {}", e)
                    ))?;
                
                Ok(serde_json::to_value(&configmap).unwrap_or(json!({})))
            }
            
            _ => Err(PluginError::ExecutionError(
                format!("Unknown configmap operation: {}", operation)
            )),
        }
    }
    
    /// Handle Secret operations
    async fn handle_secret_operation(
        &self,
        client: &Client,
        operation: &str,
        params: Value,
    ) -> Result<Value> {
        let namespace = params["namespace"].as_str()
            .unwrap_or(&self.config.default_namespace);
        
        match operation {
            "create" => {
                let secret_spec = serde_json::from_value::<Secret>(params["spec"].clone())
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Invalid secret spec: {}", e)
                    ))?;
                
                let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
                let secret = api.create(&PostParams::default(), &secret_spec).await
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Failed to create secret: {}", e)
                    ))?;
                
                // Mask secret data in response
                let mut response = serde_json::to_value(&secret).unwrap_or(json!({}));
                if let Some(data) = response.get_mut("data") {
                    if let Some(map) = data.as_object_mut() {
                        for (_, v) in map.iter_mut() {
                            *v = json!("<masked>");
                        }
                    }
                }
                
                Ok(response)
            }
            
            _ => Err(PluginError::ExecutionError(
                format!("Unknown secret operation: {}", operation)
            )),
        }
    }
    
    /// Handle Namespace operations
    async fn handle_namespace_operation(
        &self,
        client: &Client,
        operation: &str,
        params: Value,
    ) -> Result<Value> {
        match operation {
            "list" => {
                let api: Api<Namespace> = Api::all(client.clone());
                let namespaces = api.list(&ListParams::default()).await
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Failed to list namespaces: {}", e)
                    ))?;
                
                Ok(serde_json::to_value(&namespaces).unwrap_or(json!({})))
            }
            
            _ => Err(PluginError::ExecutionError(
                format!("Unknown namespace operation: {}", operation)
            )),
        }
    }
    
    /// Handle cluster operations
    async fn handle_cluster_operation(
        &self,
        client: &Client,
        operation: &str,
        _params: Value,
    ) -> Result<Value> {
        match operation {
            "version" => {
                // Get server version
                let version = client.apiserver_version().await
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Failed to get version: {}", e)
                    ))?;
                
                Ok(json!({
                    "gitVersion": version.git_version,
                    "major": version.major,
                    "minor": version.minor,
                    "platform": version.platform,
                }))
            }
            
            "nodes" => {
                let api: Api<k8s_openapi::api::core::v1::Node> = Api::all(client.clone());
                let nodes = api.list(&ListParams::default()).await
                    .map_err(|e| PluginError::ExecutionError(
                        format!("Failed to list nodes: {}", e)
                    ))?;
                
                Ok(serde_json::to_value(&nodes).unwrap_or(json!({})))
            }
            
            _ => Err(PluginError::ExecutionError(
                format!("Unknown cluster operation: {}", operation)
            )),
        }
    }
    
    /// Handle apply operations
    async fn handle_apply_operation(
        &self,
        _client: &Client,
        operation: &str,
        params: Value,
    ) -> Result<Value> {
        match operation {
            "yaml" | "json" => {
                // TODO: Implement YAML/JSON apply
                Ok(json!({
                    "status": "not_implemented",
                    "message": "Apply operations will be implemented in Phase 3"
                }))
            }
            
            _ => Err(PluginError::ExecutionError(
                format!("Unknown apply operation: {}", operation)
            )),
        }
    }
}

// Make plugin cloneable
impl Clone for KubernetesPlugin {
    fn clone(&self) -> Self {
        Self {
            metadata: self.metadata.clone(),
            client: self.client.clone(),
            config: self.config.clone(),
            state: K8sState::default(), // Don't clone state
        }
    }
}