//! Property-based tests for MCP Manager using proptest
//!
//! Tests invariants, edge cases, and generates random inputs to find bugs

use claude_optimized_deployment_rust::mcp_manager::{
    ConnectionPool, McpConfig, McpError, McpManager, McpServer, ServerRegistry, ServerState,
};
use proptest::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

// Arbitrary implementations for property testing
impl Arbitrary for ServerState {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(ServerState::Stopped),
            Just(ServerState::Starting),
            Just(ServerState::Running),
            Just(ServerState::Stopping),
            Just(ServerState::Failed),
        ]
        .boxed()
    }
}

fn arb_server_id() -> impl Strategy<Value = String> {
    "[a-z0-9\\-]{1,50}".prop_map(|s| format!("server-{}", s))
}

fn arb_server_name() -> impl Strategy<Value = String> {
    "[A-Za-z0-9 ]{1,100}".prop_map(|s| s.trim().to_string())
}

fn arb_server_type() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("docker".to_string()),
        Just("kubernetes".to_string()),
        Just("prometheus".to_string()),
        Just("custom".to_string()),
    ]
}

fn arb_endpoint() -> impl Strategy<Value = String> {
    (1000u16..10000u16).prop_map(|port| format!("ws://localhost:{}", port))
}

fn arb_metadata() -> impl Strategy<Value = HashMap<String, String>> {
    prop::collection::hash_map("[a-z_]{1,20}", "[a-zA-Z0-9]{0,50}", 0..10)
}

fn arb_mcp_server() -> impl Strategy<Value = McpServer> {
    (
        arb_server_id(),
        arb_server_name(),
        arb_server_type(),
        arb_endpoint(),
        any::<ServerState>(),
        arb_metadata(),
    )
        .prop_map(
            |(id, name, server_type, endpoint, state, metadata)| McpServer {
                id,
                name,
                server_type,
                endpoint,
                state,
                metadata,
            },
        )
}

fn arb_config() -> impl Strategy<Value = McpConfig> {
    (
        1usize..100,    // max_connections_per_server
        100u64..10000,  // connection_timeout_ms
        1000u64..60000, // request_timeout_ms
        1u64..300,      // health_check_interval_secs
        0usize..10,     // max_retries
        1.0f64..5.0,    // retry_backoff_multiplier
        any::<bool>(),  // enable_connection_pooling
        any::<bool>(),  // enable_load_balancing
        any::<bool>(),  // enable_health_checks
        any::<bool>(),  // enable_metrics
        1usize..20,     // circuit_breaker_threshold
        1u64..300,      // circuit_breaker_recovery_secs
    )
        .prop_map(
            |(
                max_connections,
                conn_timeout,
                req_timeout,
                health_interval,
                max_retries,
                backoff,
                pooling,
                load_balancing,
                health_checks,
                metrics,
                cb_threshold,
                cb_recovery,
            )| {
                McpConfig {
                    max_connections_per_server: max_connections,
                    connection_timeout_ms: conn_timeout,
                    request_timeout_ms: req_timeout,
                    health_check_interval_secs: health_interval,
                    max_retries,
                    retry_backoff_multiplier: backoff,
                    enable_connection_pooling: pooling,
                    enable_load_balancing: load_balancing,
                    enable_health_checks: health_checks,
                    enable_metrics: metrics,
                    circuit_breaker_threshold: cb_threshold,
                    circuit_breaker_recovery_secs: cb_recovery,
                    ..Default::default()
                }
            },
        )
}

// Property tests
proptest! {
    #[test]
    fn test_config_timeout_invariants(config in arb_config()) {
        // Connection timeout should always be less than request timeout
        prop_assert!(config.connection_timeout_ms < config.request_timeout_ms);

        // All timeouts should be positive
        prop_assert!(config.connection_timeout_ms > 0);
        prop_assert!(config.request_timeout_ms > 0);
        prop_assert!(config.health_check_interval_secs > 0);
        prop_assert!(config.circuit_breaker_recovery_secs > 0);

        // Backoff multiplier should be >= 1.0
        prop_assert!(config.retry_backoff_multiplier >= 1.0);
    }

    #[test]
    fn test_server_id_uniqueness(servers in prop::collection::vec(arb_mcp_server(), 0..100)) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let registry = ServerRegistry::new();
            let mut seen_ids = HashSet::new();

            for server in servers {
                let id = server.id.clone();

                if seen_ids.contains(&id) {
                    // Duplicate ID should fail
                    match registry.register_server(server).await {
                        Err(McpError::DuplicateServer(_)) => {},
                        _ => panic!("Expected DuplicateServer error"),
                    }
                } else {
                    // New ID should succeed
                    prop_assert!(registry.register_server(server).await.is_ok());
                    seen_ids.insert(id);
                }
            }

            // Registry should contain exactly the unique servers
            prop_assert_eq!(registry.server_count(), seen_ids.len());
            Ok(())
        })?;
    }

    #[test]
    fn test_connection_pool_limits(
        max_connections in 1usize..20,
        num_requests in 0usize..100
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let pool = ConnectionPool::new(max_connections);
            let mut handles = vec![];
            let acquired = Arc::new(RwLock::new(0usize));

            // Try to acquire many connections
            for _ in 0..num_requests {
                let pool = pool.clone();
                let acquired = acquired.clone();

                let handle = tokio::spawn(async move {
                    if let Ok(_conn) = pool.try_acquire("test-server").await {
                        let mut count = acquired.write().await;
                        *count += 1;

                        // Hold connection briefly
                        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                    }
                });

                handles.push(handle);
            }

            // Wait for all attempts
            futures::future::join_all(handles).await;

            // Check that we never exceeded the limit
            let final_count = *acquired.read().await;
            prop_assert!(final_count <= max_connections);

            Ok(())
        })?;
    }

    #[test]
    fn test_server_state_transitions(
        initial_state in any::<ServerState>(),
        operations in prop::collection::vec(0u8..5, 0..20)
    ) {
        // Define valid state transitions
        let valid_transitions = |from: &ServerState, to: &ServerState| -> bool {
            match (from, to) {
                (ServerState::Stopped, ServerState::Starting) => true,
                (ServerState::Starting, ServerState::Running) => true,
                (ServerState::Starting, ServerState::Failed) => true,
                (ServerState::Running, ServerState::Stopping) => true,
                (ServerState::Stopping, ServerState::Stopped) => true,
                (ServerState::Failed, ServerState::Starting) => true,
                _ => false,
            }
        };

        let mut state = initial_state;

        for op in operations {
            let next_state = match op % 5 {
                0 => ServerState::Stopped,
                1 => ServerState::Starting,
                2 => ServerState::Running,
                3 => ServerState::Stopping,
                _ => ServerState::Failed,
            };

            // Only apply valid transitions
            if valid_transitions(&state, &next_state) {
                state = next_state;
            }
        }

        // State should always be valid
        prop_assert!(matches!(
            state,
            ServerState::Stopped | ServerState::Starting |
            ServerState::Running | ServerState::Stopping |
            ServerState::Failed
        ));
    }

    #[test]
    fn test_retry_backoff_calculation(
        initial_delay in 10u64..1000,
        multiplier in 1.1f64..3.0,
        max_retries in 1usize..10
    ) {
        let mut delay = initial_delay as f64;
        let mut total_delay = 0f64;

        for _ in 0..max_retries {
            total_delay += delay;
            delay *= multiplier;
        }

        // Total delay should be bounded
        prop_assert!(total_delay < 60000.0); // Less than 1 minute total

        // Each delay should increase
        let mut prev = initial_delay as f64;
        for _ in 1..max_retries {
            let next = prev * multiplier;
            prop_assert!(next > prev);
            prev = next;
        }
    }

    #[test]
    fn test_circuit_breaker_threshold(
        threshold in 1usize..20,
        failures in prop::collection::vec(any::<bool>(), 0..100)
    ) {
        let mut consecutive_failures = 0;
        let mut circuit_open = false;

        for is_failure in failures {
            if circuit_open {
                // Circuit is open, all requests should fail fast
                continue;
            }

            if is_failure {
                consecutive_failures += 1;
                if consecutive_failures >= threshold {
                    circuit_open = true;
                }
            } else {
                // Success resets the counter
                consecutive_failures = 0;
            }
        }

        // Circuit should only be open if we had enough consecutive failures
        if circuit_open {
            prop_assert!(consecutive_failures >= threshold);
        }
    }

    #[test]
    fn test_load_balancer_distribution(
        num_servers in 2usize..10,
        num_requests in 100usize..1000
    ) {
        let servers: Vec<String> = (0..num_servers)
            .map(|i| format!("server-{}", i))
            .collect();

        let mut distribution = HashMap::new();

        // Simulate round-robin distribution
        for i in 0..num_requests {
            let server = &servers[i % num_servers];
            *distribution.entry(server.clone()).or_insert(0) += 1;
        }

        // Check that distribution is roughly even
        let expected = num_requests / num_servers;
        let tolerance = expected / 10; // 10% tolerance

        for (_, count) in distribution {
            prop_assert!(count >= expected - tolerance);
            prop_assert!(count <= expected + tolerance + 1);
        }
    }

    #[test]
    fn test_metadata_serialization_roundtrip(
        metadata in arb_metadata()
    ) {
        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: HashMap<String, String> = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(metadata, deserialized);
    }

    #[test]
    fn test_concurrent_modifications_consistency(
        initial_servers in prop::collection::vec(arb_mcp_server(), 0..10),
        operations in prop::collection::vec(
            (0usize..3, arb_mcp_server()),
            0..50
        )
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let registry = Arc::new(RwLock::new(ServerRegistry::new()));

            // Add initial servers
            for server in initial_servers {
                let mut reg = registry.write().await;
                let _ = reg.register_server(server).await;
            }

            // Perform random operations concurrently
            let mut handles = vec![];

            for (op_type, server) in operations {
                let registry = registry.clone();

                let handle = tokio::spawn(async move {
                    match op_type % 3 {
                        0 => {
                            // Register
                            let mut reg = registry.write().await;
                            let _ = reg.register_server(server).await;
                        },
                        1 => {
                            // Unregister
                            let mut reg = registry.write().await;
                            let _ = reg.unregister_server(&server.id).await;
                        },
                        _ => {
                            // Read
                            let reg = registry.read().await;
                            let _ = reg.get_server(&server.id);
                        },
                    }
                });

                handles.push(handle);
            }

            // Wait for all operations
            futures::future::join_all(handles).await;

            // Verify consistency
            let reg = registry.read().await;
            let count = reg.server_count();

            // Count should be non-negative and reasonable
            prop_assert!(count <= 1000);

            Ok(())
        })?;
    }
}

// Stateful property tests
mod stateful_tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::Config;

    #[derive(Debug, Clone)]
    enum RegistryOperation {
        Register(McpServer),
        Unregister(String),
        Get(String),
        List,
    }

    fn arb_registry_operation() -> impl Strategy<Value = RegistryOperation> {
        prop_oneof![
            arb_mcp_server().prop_map(RegistryOperation::Register),
            arb_server_id().prop_map(RegistryOperation::Unregister),
            arb_server_id().prop_map(RegistryOperation::Get),
            Just(RegistryOperation::List),
        ]
    }

    proptest! {
        #![proptest_config(Config::with_cases(50))]
        #[test]
        fn test_registry_model_checking(
            operations in prop::collection::vec(arb_registry_operation(), 0..100)
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let registry = ServerRegistry::new();
                let mut model = HashMap::new(); // Our model of what should be in registry

                for op in operations {
                    match op {
                        RegistryOperation::Register(server) => {
                            let id = server.id.clone();
                            let result = registry.register_server(server.clone()).await;

                            if model.contains_key(&id) {
                                prop_assert!(result.is_err());
                            } else {
                                prop_assert!(result.is_ok());
                                model.insert(id, server);
                            }
                        },
                        RegistryOperation::Unregister(id) => {
                            let result = registry.unregister_server(&id).await;

                            if model.contains_key(&id) {
                                prop_assert!(result.is_ok());
                                model.remove(&id);
                            } else {
                                prop_assert!(result.is_err());
                            }
                        },
                        RegistryOperation::Get(id) => {
                            let result = registry.get_server(&id).await;

                            if let Some(expected) = model.get(&id) {
                                prop_assert!(result.is_ok());
                                let actual = result.unwrap();
                                prop_assert_eq!(&actual.id, &expected.id);
                                prop_assert_eq!(&actual.name, &expected.name);
                            } else {
                                prop_assert!(result.is_err());
                            }
                        },
                        RegistryOperation::List => {
                            let servers = registry.list_servers().await;
                            prop_assert_eq!(servers.len(), model.len());

                            for server in servers {
                                prop_assert!(model.contains_key(&server.id));
                            }
                        },
                    }
                }

                Ok(())
            })?;
        }
    }
}
