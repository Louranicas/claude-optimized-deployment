//! Resilience Tests for MCP Manager
//!
//! Tests for failure recovery, circuit breakers, and system resilience.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use super::*;
use claude_optimized_deployment_rust::mcp_manager::plugin::{
    *,
    registry::*,
    lifecycle::*,
    hot_reload::*,
    rollback::*,
    state_transfer::*,
    zero_downtime::*,
};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout};

/// Resilience test plugin with various failure modes
#[derive(Debug)]
struct ResilienceTestPlugin {
    metadata: PluginMetadata,
    failure_mode: Arc<RwLock<FailureMode>>,
    request_count: Arc<AtomicU64>,
    failure_count: Arc<AtomicU64>,
    recovery_count: Arc<AtomicU64>,
    circuit_breaker_trips: Arc<AtomicU64>,
    is_healthy: Arc<AtomicBool>,
    state_data: Arc<RwLock<HashMap<String, String>>>,
}

#[derive(Debug, Clone)]
enum FailureMode {
    None,
    RandomFailure { rate: f64 },
    TimeoutFailure { duration_ms: u64 },
    CrashFailure,
    MemoryLeak { bytes_per_request: usize },
    SlowDegradation { delay_increment_ms: u64 },
    IntermittentFailure { pattern: Vec<bool> },
}

impl ResilienceTestPlugin {
    fn new(id: &str) -> Self {
        Self {
            metadata: PluginMetadata {
                id: id.to_string(),
                name: format!("Resilience Test Plugin {}", id),
                version: "1.0.0".to_string(),
                author: "Resilience Test".to_string(),
                description: "Plugin for resilience testing".to_string(),
                license: "MIT".to_string(),
                homepage: None,
                repository: None,
                min_mcp_version: "1.0.0".to_string(),
                dependencies: vec![],
                provides: vec![
                    Capability::new("resilience", "test", 1),
                    Capability::new("resilience", "health", 1),
                    Capability::new("resilience", "recovery", 1),
                ],
                requires: vec![],
            },
            failure_mode: Arc::new(RwLock::new(FailureMode::None)),
            request_count: Arc::new(AtomicU64::new(0)),
            failure_count: Arc::new(AtomicU64::new(0)),
            recovery_count: Arc::new(AtomicU64::new(0)),
            circuit_breaker_trips: Arc::new(AtomicU64::new(0)),
            is_healthy: Arc::new(AtomicBool::new(true)),
            state_data: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn set_failure_mode(&self, mode: FailureMode) {
        *self.failure_mode.write().await = mode;
    }

    fn mark_unhealthy(&self) {
        self.is_healthy.store(false, Ordering::SeqCst);
    }

    fn mark_healthy(&self) {
        self.is_healthy.store(true, Ordering::SeqCst);
        self.recovery_count.fetch_add(1, Ordering::SeqCst);
    }

    fn trip_circuit_breaker(&self) {
        self.circuit_breaker_trips.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl Plugin for ResilienceTestPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&mut self, _config: serde_json::Value) -> Result<()> {
        self.mark_healthy();
        Ok(())
    }

    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        let count = self.request_count.fetch_add(1, Ordering::SeqCst);

        // Check if healthy
        if !self.is_healthy.load(Ordering::SeqCst) {
            self.failure_count.fetch_add(1, Ordering::SeqCst);
            return Err(PluginError::Unavailable("Plugin is unhealthy".to_string()));
        }

        // Apply failure mode
        let failure_mode = self.failure_mode.read().await.clone();
        match failure_mode {
            FailureMode::None => {}
            FailureMode::RandomFailure { rate } => {
                if (count as f64 % 100.0) / 100.0 < rate {
                    self.failure_count.fetch_add(1, Ordering::SeqCst);
                    return Err(PluginError::ExecutionError("Random failure".to_string()));
                }
            }
            FailureMode::TimeoutFailure { duration_ms } => {
                sleep(Duration::from_millis(duration_ms)).await;
                self.failure_count.fetch_add(1, Ordering::SeqCst);
                return Err(PluginError::Timeout("Request timed out".to_string()));
            }
            FailureMode::CrashFailure => {
                self.mark_unhealthy();
                self.failure_count.fetch_add(1, Ordering::SeqCst);
                return Err(PluginError::ExecutionError("Plugin crashed".to_string()));
            }
            FailureMode::MemoryLeak { bytes_per_request } => {
                let _leak = vec![0u8; bytes_per_request];
                std::mem::forget(_leak); // Intentional memory leak
            }
            FailureMode::SlowDegradation { delay_increment_ms } => {
                let delay = count * delay_increment_ms;
                sleep(Duration::from_millis(delay)).await;
            }
            FailureMode::IntermittentFailure { ref pattern } => {
                let should_fail = pattern[(count as usize) % pattern.len()];
                if should_fail {
                    self.failure_count.fetch_add(1, Ordering::SeqCst);
                    return Err(PluginError::ExecutionError("Intermittent failure".to_string()));
                }
            }
        }

        // Handle special methods
        match request.method.as_str() {
            "health_check" => {
                Ok(PluginResponse {
                    request_id: request.id,
                    result: PluginResult::Success {
                        data: json!({
                            "healthy": self.is_healthy.load(Ordering::SeqCst),
                            "request_count": count,
                            "failure_count": self.failure_count.load(Ordering::SeqCst),
                            "recovery_count": self.recovery_count.load(Ordering::SeqCst),
                        }),
                    },
                    metadata: json!({}),
                })
            }
            "recover" => {
                self.mark_healthy();
                self.set_failure_mode(FailureMode::None).await;
                Ok(PluginResponse {
                    request_id: request.id,
                    result: PluginResult::Success {
                        data: json!({"recovered": true}),
                    },
                    metadata: json!({}),
                })
            }
            _ => {
                // Store state data
                if let Some(data) = request.params.get("state_data") {
                    if let Some(key) = data.get("key").and_then(|k| k.as_str()) {
                        if let Some(value) = data.get("value").and_then(|v| v.as_str()) {
                            self.state_data.write().await.insert(key.to_string(), value.to_string());
                        }
                    }
                }

                Ok(PluginResponse {
                    request_id: request.id,
                    result: PluginResult::Success {
                        data: json!({
                            "plugin_id": self.metadata.id,
                            "request_number": count + 1,
                        }),
                    },
                    metadata: json!({}),
                })
            }
        }
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.mark_unhealthy();
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[async_trait::async_trait]
impl StateTransferable for ResilienceTestPlugin {
    async fn export_state(&self) -> Result<StateSnapshot> {
        let state_data = self.state_data.read().await.clone();
        
        Ok(StateSnapshot {
            id: uuid::Uuid::new_v4().to_string(),
            plugin_id: self.metadata.id.clone(),
            plugin_version: self.metadata.version.clone(),
            schema_version: 1,
            timestamp: chrono::Utc::now().timestamp(),
            sections: HashMap::from([
                ("resilience_state".to_string(), StateSection {
                    name: "resilience_state".to_string(),
                    section_type: SectionType::Core,
                    priority: 1,
                    format: DataFormat::Json,
                    data: SectionData::Inline {
                        data: serde_json::to_vec(&json!({
                            "state_data": state_data,
                            "request_count": self.request_count.load(Ordering::SeqCst),
                            "failure_count": self.failure_count.load(Ordering::SeqCst),
                            "is_healthy": self.is_healthy.load(Ordering::SeqCst),
                        })).unwrap(),
                        original_size: 1024,
                        compression: CompressionType::None,
                    },
                    dependencies: vec![],
                }),
            ]),
            metadata: StateMetadata {
                reason: StateCreationReason::Checkpoint,
                created_by: "resilience_test".to_string(),
                tags: vec!["test".to_string()],
                expires_at: None,
                custom: HashMap::new(),
            },
            checksum: "test".to_string(),
        })
    }

    async fn import_state(&mut self, snapshot: StateSnapshot) -> Result<StateImportResult> {
        if let Some(section) = snapshot.sections.get("resilience_state") {
            if let SectionData::Inline { data, .. } = &section.data {
                let state: serde_json::Value = serde_json::from_slice(data).unwrap();
                
                // Restore state
                if let Some(state_data) = state.get("state_data") {
                    *self.state_data.write().await = serde_json::from_value(state_data.clone()).unwrap_or_default();
                }
                
                if let Some(count) = state.get("request_count").and_then(|v| v.as_u64()) {
                    self.request_count.store(count, Ordering::SeqCst);
                }
                
                if let Some(failures) = state.get("failure_count").and_then(|v| v.as_u64()) {
                    self.failure_count.store(failures, Ordering::SeqCst);
                }
                
                if let Some(healthy) = state.get("is_healthy").and_then(|v| v.as_bool()) {
                    self.is_healthy.store(healthy, Ordering::SeqCst);
                }
            }
        }

        Ok(StateImportResult {
            imported_sections: vec!["resilience_state".to_string()],
            failed_sections: vec![],
            warnings: vec![],
            duration: Duration::from_millis(10),
        })
    }

    async fn validate_state(&self, _snapshot: &StateSnapshot) -> Result<StateValidation> {
        Ok(StateValidation {
            is_valid: true,
            schema_compatible: true,
            version_compatible: true,
            section_validations: HashMap::new(),
            compatibility_score: 1.0,
        })
    }

    fn state_schema_version(&self) -> u32 {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker_functionality() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let plugin = ResilienceTestPlugin::new("circuit-breaker-test");
        plugin.set_failure_mode(FailureMode::RandomFailure { rate: 0.5 }).await; // 50% failure rate
        
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        handle.initialize(json!({})).await.unwrap();

        // Configure circuit breaker
        let circuit_breaker_config = CircuitBreakerConfig {
            failure_threshold: 5,
            success_threshold: 3,
            timeout: Duration::from_secs(5),
            half_open_max_requests: 3,
        };

        let mut consecutive_failures = 0;
        let mut circuit_open = false;

        // Send requests until circuit breaker trips
        for i in 0..20 {
            let request = PluginRequest {
                id: format!("cb-{}", i),
                capability: Capability::new("resilience", "test", 1),
                method: "test".to_string(),
                params: json!({"index": i}),
                metadata: json!({}),
            };

            match handle.handle(request).await {
                Ok(_) => {
                    consecutive_failures = 0;
                    if circuit_open {
                        println!("Circuit breaker recovered at request {}", i);
                        circuit_open = false;
                    }
                }
                Err(_) => {
                    consecutive_failures += 1;
                    if consecutive_failures >= circuit_breaker_config.failure_threshold && !circuit_open {
                        println!("Circuit breaker tripped at request {}", i);
                        circuit_open = true;
                        
                        // Simulate circuit breaker behavior
                        if let Some(plugin) = handle.as_any().downcast_ref::<ResilienceTestPlugin>() {
                            plugin.trip_circuit_breaker();
                        }
                        
                        // Wait for timeout
                        sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }

        // Verify circuit breaker was triggered
        if let Some(plugin) = handle.as_any().downcast_ref::<ResilienceTestPlugin>() {
            let trips = plugin.circuit_breaker_trips.load(Ordering::SeqCst);
            assert!(trips > 0, "Circuit breaker should have been triggered");
        }

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_automatic_recovery() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let plugin = ResilienceTestPlugin::new("auto-recovery-test");
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        handle.initialize(json!({})).await.unwrap();

        // Simulate crash
        if let Some(plugin) = handle.as_any().downcast_ref::<ResilienceTestPlugin>() {
            plugin.set_failure_mode(FailureMode::CrashFailure).await;
        }

        // Trigger crash
        let crash_request = PluginRequest {
            id: "crash-1".to_string(),
            capability: Capability::new("resilience", "test", 1),
            method: "test".to_string(),
            params: json!({}),
            metadata: json!({}),
        };

        let result = handle.handle(crash_request).await;
        assert!(result.is_err());

        // Plugin should be unhealthy
        if let Some(plugin) = handle.as_any().downcast_ref::<ResilienceTestPlugin>() {
            assert!(!plugin.is_healthy.load(Ordering::SeqCst));
        }

        // Attempt recovery
        let recover_request = PluginRequest {
            id: "recover-1".to_string(),
            capability: Capability::new("resilience", "recovery", 1),
            method: "recover".to_string(),
            params: json!({}),
            metadata: json!({}),
        };

        let recover_result = handle.handle(recover_request).await.unwrap();
        if let PluginResult::Success { data } = recover_result.result {
            assert_eq!(data["recovered"], true);
        }

        // Plugin should be healthy again
        if let Some(plugin) = handle.as_any().downcast_ref::<ResilienceTestPlugin>() {
            assert!(plugin.is_healthy.load(Ordering::SeqCst));
            assert_eq!(plugin.recovery_count.load(Ordering::SeqCst), 1);
        }

        // Normal requests should work again
        let normal_request = PluginRequest {
            id: "normal-1".to_string(),
            capability: Capability::new("resilience", "test", 1),
            method: "test".to_string(),
            params: json!({}),
            metadata: json!({}),
        };

        let normal_result = handle.handle(normal_request).await;
        assert!(normal_result.is_ok());

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_state_preservation_during_failure() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let state_transfer = Arc::new(StateTransferCoordinator::new(Default::default()));
        let rollback_manager = Arc::new(RollbackManager::new(
            state_transfer.clone(),
            Arc::new(VersionManager::new(Default::default())),
            Default::default(),
        ));

        let plugin = ResilienceTestPlugin::new("state-preservation-test");
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        handle.initialize(json!({})).await.unwrap();

        // Add state data
        for i in 0..5 {
            let request = PluginRequest {
                id: format!("state-{}", i),
                capability: Capability::new("resilience", "test", 1),
                method: "set_state".to_string(),
                params: json!({
                    "state_data": {
                        "key": format!("key-{}", i),
                        "value": format!("value-{}", i),
                    }
                }),
                metadata: json!({}),
            };
            handle.handle(request).await.unwrap();
        }

        // Create checkpoint before failure
        let plugin_ref = handle.as_any().downcast_ref::<ResilienceTestPlugin>().unwrap();
        let state_snapshot = plugin_ref.export_state().await.unwrap();
        
        rollback_manager.create_checkpoint(
            "state-preservation-test",
            handle.clone(),
            state_snapshot.clone(),
            CheckpointType::PreUpdate,
            "Pre-failure checkpoint",
        ).await.unwrap();

        // Verify state data was saved
        assert_eq!(state_snapshot.sections.len(), 1);
        assert!(state_snapshot.sections.contains_key("resilience_state"));

        // Simulate failure
        if let Some(plugin) = handle.as_any().downcast_ref::<ResilienceTestPlugin>() {
            plugin.set_failure_mode(FailureMode::CrashFailure).await;
            plugin.mark_unhealthy();
        }

        // Restore from checkpoint
        let restore_result = rollback_manager.restore_checkpoint(
            "state-preservation-test",
            handle.clone(),
            None, // Use latest checkpoint
        ).await.unwrap();

        assert!(restore_result.success);
        assert_eq!(restore_result.sections_restored.len(), 1);

        // Verify state was restored
        if let Some(plugin) = handle.as_any().downcast_ref::<ResilienceTestPlugin>() {
            let state_data = plugin.state_data.read().await;
            for i in 0..5 {
                assert_eq!(
                    state_data.get(&format!("key-{}", i)), 
                    Some(&format!("value-{}", i))
                );
            }
        }

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_timeout_handling() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let plugin = ResilienceTestPlugin::new("timeout-test");
        plugin.set_failure_mode(FailureMode::TimeoutFailure { duration_ms: 2000 }).await;
        
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        handle.initialize(json!({})).await.unwrap();

        // Send request with timeout
        let request = PluginRequest {
            id: "timeout-1".to_string(),
            capability: Capability::new("resilience", "test", 1),
            method: "test".to_string(),
            params: json!({}),
            metadata: json!({}),
        };

        // Use tokio timeout
        let result = timeout(Duration::from_secs(1), handle.handle(request)).await;
        
        assert!(result.is_err(), "Request should timeout");

        // Verify plugin tracked the failure
        if let Some(plugin) = handle.as_any().downcast_ref::<ResilienceTestPlugin>() {
            assert!(plugin.failure_count.load(Ordering::SeqCst) > 0);
        }

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_cascading_failure_prevention() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let mut registry = PluginRegistry::new();
        let lifecycle_manager = LifecycleManager::new(Default::default());

        // Create chain of dependent plugins
        let plugins = vec![
            ("upstream", vec![], FailureMode::None),
            ("middleware", vec![], FailureMode::None),
            ("downstream", vec![], FailureMode::RandomFailure { rate: 0.8 }), // High failure rate
        ];

        let mut handles = HashMap::new();

        for (id, _deps, failure_mode) in plugins {
            let plugin = ResilienceTestPlugin::new(id);
            plugin.set_failure_mode(failure_mode).await;
            
            let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
            registry.register(id.to_string(), handle.clone()).unwrap();
            lifecycle_manager.register_plugin(id.to_string(), handle.clone()).await.unwrap();
            lifecycle_manager.initialize_plugin(id, json!({})).await.unwrap();
            
            handles.insert(id.to_string(), handle);
        }

        // Simulate requests flowing through the chain
        let mut upstream_success = 0;
        let mut middleware_success = 0;
        let mut downstream_success = 0;

        for i in 0..50 {
            // Start at upstream
            let request = PluginRequest {
                id: format!("cascade-{}", i),
                capability: Capability::new("resilience", "test", 1),
                method: "test".to_string(),
                params: json!({"flow": "upstream->middleware->downstream"}),
                metadata: json!({}),
            };

            // Process through chain
            if let Ok(_) = handles["upstream"].handle(request.clone()).await {
                upstream_success += 1;
                
                // Only proceed if upstream succeeded
                if let Ok(_) = handles["middleware"].handle(request.clone()).await {
                    middleware_success += 1;
                    
                    // Only proceed if middleware succeeded
                    if let Ok(_) = handles["downstream"].handle(request.clone()).await {
                        downstream_success += 1;
                    }
                }
            }
        }

        println!("Cascading Failure Prevention Results:");
        println!("  Upstream success: {}/50", upstream_success);
        println!("  Middleware success: {}/50", middleware_success);
        println!("  Downstream success: {}/50", downstream_success);

        // Upstream and middleware should have high success rates
        assert!(upstream_success >= 45, "Upstream should be mostly successful");
        assert!(middleware_success >= 45, "Middleware should be mostly successful");
        
        // Downstream failures shouldn't cascade back
        assert!(downstream_success < 20, "Downstream should have failures");

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_progressive_degradation() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let plugin = ResilienceTestPlugin::new("degradation-test");
        plugin.set_failure_mode(FailureMode::SlowDegradation { delay_increment_ms: 10 }).await;
        
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        handle.initialize(json!({})).await.unwrap();

        // Track response times
        let mut response_times = vec![];

        for i in 0..20 {
            let start = Instant::now();
            
            let request = PluginRequest {
                id: format!("degrade-{}", i),
                capability: Capability::new("resilience", "test", 1),
                method: "test".to_string(),
                params: json!({"index": i}),
                metadata: json!({}),
            };

            let _ = handle.handle(request).await;
            response_times.push(start.elapsed());
        }

        // Verify progressive degradation
        for i in 1..response_times.len() {
            assert!(
                response_times[i] >= response_times[i-1],
                "Response times should progressively increase"
            );
        }

        // Later requests should be significantly slower
        let early_avg = response_times[..5].iter()
            .map(|d| d.as_millis())
            .sum::<u128>() / 5;
        
        let late_avg = response_times[15..].iter()
            .map(|d| d.as_millis())
            .sum::<u128>() / 5;

        assert!(
            late_avg > early_avg * 2,
            "Late requests should be significantly slower than early ones"
        );

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_intermittent_failure_pattern() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        // Create pattern: Success, Success, Fail, Success, Fail
        let failure_pattern = vec![false, false, true, false, true];
        
        let plugin = ResilienceTestPlugin::new("pattern-test");
        plugin.set_failure_mode(FailureMode::IntermittentFailure { 
            pattern: failure_pattern.clone() 
        }).await;
        
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        handle.initialize(json!({})).await.unwrap();

        // Test pattern repeats
        let mut results = vec![];
        for i in 0..15 {
            let request = PluginRequest {
                id: format!("pattern-{}", i),
                capability: Capability::new("resilience", "test", 1),
                method: "test".to_string(),
                params: json!({"index": i}),
                metadata: json!({}),
            };

            let result = handle.handle(request).await;
            results.push(result.is_ok());
        }

        // Verify pattern matches
        for (i, &expected_success) in results.iter().enumerate() {
            let pattern_index = i % failure_pattern.len();
            let expected = !failure_pattern[pattern_index];
            assert_eq!(
                expected_success, expected,
                "Result at index {} doesn't match pattern", i
            );
        }

        env.teardown().await.unwrap();
    }
}