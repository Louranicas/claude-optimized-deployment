use claude_optimized_deployment_rust::*;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_end_to_end_command_execution() {
    // Initialize system
    let system = System::builder()
        .with_memory_limit(1024 * 1024 * 1024) // 1GB
        .with_max_parallel_tasks(10)
        .build()
        .await
        .expect("Failed to build system");

    // Create command chain
    let commands = vec![
        Command::new("echo", vec!["Hello"]),
        Command::new("echo", vec!["World"]),
    ];

    // Execute with optimization
    let optimizer = CommandOptimizer::new();
    let optimized = optimizer.optimize(&commands).unwrap();

    let results = system.execute_chain(&optimized).await.unwrap();

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].output.trim(), "Hello");
    assert_eq!(results[1].output.trim(), "World");
    assert!(results[0].duration_ms < 1000);
}

#[tokio::test]
async fn test_mcp_integration_full_lifecycle() {
    // Start MCP manager
    let manager = MCPManager::new(MCPConfig {
        port: 0, // Random port
        max_connections: 100,
        enable_tls: false,
    })
    .await
    .unwrap();

    let addr = manager.local_addr();

    // Connect client
    let client = MCPClient::connect(format!("ws://{}", addr))
        .await
        .expect("Failed to connect");

    // Initialize session
    let init_response = client
        .initialize(InitializeParams {
            client_info: ClientInfo {
                name: "test_client".to_string(),
                version: "1.0.0".to_string(),
            },
            capabilities: Default::default(),
        })
        .await
        .unwrap();

    assert_eq!(init_response.protocol_version, "1.0");

    // List available tools
    let tools = client.list_tools().await.unwrap();
    assert!(!tools.is_empty());
    assert!(tools.iter().any(|t| t.name == "execute_command"));

    // Execute a tool
    let result = client
        .execute_tool(ToolExecutionParams {
            tool: "execute_command".to_string(),
            arguments: serde_json::json!({
                "command": "echo",
                "args": ["test"]
            }),
        })
        .await
        .unwrap();

    assert_eq!(result.status, "success");
    assert_eq!(result.output.as_ref().unwrap().trim(), "test");

    // Test resource management
    let resources = client.list_resources().await.unwrap();
    assert!(!resources.is_empty());

    // Subscribe to events
    let mut event_stream = client.subscribe("system_events").await.unwrap();

    // Trigger an event
    manager
        .emit_event(
            "test_event",
            serde_json::json!({
                "message": "Hello from test"
            }),
        )
        .await
        .unwrap();

    // Receive event
    let event = timeout(Duration::from_secs(5), event_stream.recv())
        .await
        .expect("Timeout waiting for event")
        .expect("Failed to receive event");

    assert_eq!(event.event_type, "test_event");

    // Shutdown
    client.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_actor_system_integration() {
    let system = ActorSystem::new();

    // Spawn multiple actors
    let actor1 = system.spawn_actor("processor").await.unwrap();
    let actor2 = system.spawn_actor("aggregator").await.unwrap();
    let actor3 = system.spawn_actor("reporter").await.unwrap();

    // Create processing pipeline
    actor1.link(&actor2).await.unwrap();
    actor2.link(&actor3).await.unwrap();

    // Send data through pipeline
    let data = vec![1, 2, 3, 4, 5];
    actor1
        .send(Message::new("process", data.clone()))
        .await
        .unwrap();

    // Wait for processing
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify result at final actor
    let result = actor3
        .receive_timeout(Duration::from_secs(1))
        .await
        .expect("Failed to receive result");

    assert_eq!(result.msg_type, "report");
    let processed_data: Vec<i32> = serde_json::from_slice(&result.payload).unwrap();
    assert_eq!(processed_data, vec![2, 4, 6, 8, 10]); // Assuming doubling

    // Test actor supervision
    actor2.crash_for_test().await;

    // Supervisor should restart actor
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(actor2.is_alive().await);

    // Pipeline should still work
    actor1
        .send(Message::new("process", vec![10]))
        .await
        .unwrap();
    let result = actor3
        .receive_timeout(Duration::from_secs(1))
        .await
        .expect("Failed to receive after restart");

    assert_eq!(result.msg_type, "report");
}

#[tokio::test]
async fn test_memory_system_integration() {
    let memory = MemorySystem::new(MemoryConfig {
        max_size_bytes: 100 * 1024 * 1024, // 100MB
        enable_compression: true,
        gc_interval: Duration::from_secs(60),
    });

    // Test basic operations
    let key = "test_key";
    let value = b"Hello, World!".to_vec();

    memory.store(key, value.clone()).await.unwrap();
    let retrieved = memory.get(key).await.unwrap().unwrap();
    assert_eq!(retrieved, value);

    // Test vector storage and search
    let vector_db = memory.vector_store();

    // Store embeddings
    let embeddings = vec![
        ("doc1", vec![0.1, 0.2, 0.3, 0.4]),
        ("doc2", vec![0.2, 0.3, 0.4, 0.5]),
        ("doc3", vec![0.9, 0.8, 0.7, 0.6]),
    ];

    for (id, embedding) in embeddings {
        vector_db.store(id, embedding).await.unwrap();
    }

    // Search similar
    let query = vec![0.15, 0.25, 0.35, 0.45];
    let results = vector_db.search_top_k(&query, 2).await.unwrap();

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].id, "doc1");
    assert_eq!(results[1].id, "doc2");

    // Test memory pressure handling
    let large_data = vec![0u8; 10 * 1024 * 1024]; // 10MB
    for i in 0..15 {
        let key = format!("large_{}", i);
        memory.store(&key, large_data.clone()).await.unwrap();
    }

    // Should trigger GC
    let stats = memory.get_stats().await;
    assert!(stats.gc_runs > 0);
    assert!(stats.bytes_freed > 0);

    // Test concurrent access
    let handles: Vec<_> = (0..10)
        .map(|i| {
            let mem = memory.clone();
            tokio::spawn(async move {
                for j in 0..100 {
                    let key = format!("concurrent_{}_{}", i, j);
                    mem.store(&key, vec![i as u8; 100]).await.unwrap();
                    mem.get(&key).await.unwrap();
                }
            })
        })
        .collect();

    for handle in handles {
        handle.await.unwrap();
    }

    // Verify consistency
    memory.verify_consistency().await.unwrap();
}

#[tokio::test]
async fn test_learning_system_integration() {
    let learner = AdaptiveLearner::new(LearnerConfig {
        model_type: ModelType::Transformer,
        learning_rate: 0.001,
        batch_size: 32,
        max_epochs: 10,
    });

    // Generate training data
    let mut training_data = Vec::new();
    for i in 0..1000 {
        let x = i as f32 / 100.0;
        let y = (x * 2.0 + 1.0) + rand::random::<f32>() * 0.1; // y = 2x + 1 + noise
        training_data.push((vec![x], vec![y]));
    }

    // Train model
    let initial_loss = learner.evaluate(&training_data).await.unwrap();

    let train_result = learner.train(&training_data).await.unwrap();
    assert!(train_result.epochs_completed > 0);
    assert!(train_result.final_loss < initial_loss);

    // Test prediction
    let test_input = vec![5.0];
    let prediction = learner.predict(&test_input).await.unwrap();
    let expected = 11.0; // 2 * 5 + 1
    assert!((prediction[0] - expected).abs() < 0.5); // Allow some error

    // Test model persistence
    let model_data = learner.export_model().await.unwrap();

    let new_learner = AdaptiveLearner::from_model(model_data).await.unwrap();
    let new_prediction = new_learner.predict(&test_input).await.unwrap();
    assert_eq!(prediction, new_prediction);

    // Test online learning
    let new_sample = (vec![10.0], vec![21.0]);
    learner.update_online(&new_sample).await.unwrap();

    let updated_prediction = learner.predict(&vec![10.0]).await.unwrap();
    assert!((updated_prediction[0] - 21.0).abs() < 1.0);
}

#[tokio::test]
async fn test_python_bindings_integration() {
    use pyo3::prelude::*;
    use pyo3::types::PyDict;

    Python::with_gil(|py| {
        // Import our module
        let module = PyModule::import(py, "claude_optimized_deployment_rust")
            .expect("Failed to import module");

        // Test command execution from Python
        let result = module
            .getattr("execute_command")
            .unwrap()
            .call1(("echo", vec!["Hello from Python"]))
            .unwrap();

        let output: String = result.getattr("output").unwrap().extract().unwrap();
        assert_eq!(output.trim(), "Hello from Python");

        // Test memory operations from Python
        let memory = module.getattr("MemorySystem").unwrap().call0().unwrap();

        memory
            .call_method1("store", ("py_key", b"Python data"))
            .unwrap();

        let retrieved = memory.call_method1("get", ("py_key",)).unwrap();

        let data: Vec<u8> = retrieved.extract().unwrap();
        assert_eq!(data, b"Python data");

        // Test async operations
        let asyncio = py.import("asyncio").unwrap();
        let coro = module
            .getattr("async_execute")
            .unwrap()
            .call1(("sleep", vec!["0.1"]))
            .unwrap();

        let result = asyncio.getattr("run").unwrap().call1((coro,)).unwrap();

        assert!(result
            .getattr("success")
            .unwrap()
            .extract::<bool>()
            .unwrap());
    });
}

#[tokio::test]
async fn test_performance_monitoring_integration() {
    let monitor = PerformanceMonitor::new();

    // Start monitoring
    monitor.start_collection().await;

    // Perform some operations
    let system = System::new();

    for _ in 0..100 {
        system.execute_command("echo", vec!["test"]).await.unwrap();
    }

    // Collect metrics
    tokio::time::sleep(Duration::from_secs(1)).await;
    let metrics = monitor.get_metrics().await;

    assert!(metrics.total_requests > 0);
    assert!(metrics.successful_requests > 0);
    assert!(metrics.average_latency_ms > 0.0);
    assert!(metrics.p99_latency_ms >= metrics.average_latency_ms);
    assert!(metrics.cpu_usage_percent >= 0.0);
    assert!(metrics.memory_usage_bytes > 0);

    // Test alerting
    monitor.set_alert_threshold("latency_p99", 100.0).await;

    // Simulate slow operation
    system.execute_command("sleep", vec!["0.2"]).await.unwrap();

    let alerts = monitor.get_active_alerts().await;
    assert!(!alerts.is_empty());
}

#[tokio::test]
async fn test_distributed_coordination() {
    // Create cluster nodes
    let node1 = ClusterNode::new("node1", "127.0.0.1:9001").await.unwrap();
    let node2 = ClusterNode::new("node2", "127.0.0.1:9002").await.unwrap();
    let node3 = ClusterNode::new("node3", "127.0.0.1:9003").await.unwrap();

    // Form cluster
    node2.join(&node1).await.unwrap();
    node3.join(&node1).await.unwrap();

    // Wait for cluster formation
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Test leader election
    let leader1 = node1.get_leader().await.unwrap();
    let leader2 = node2.get_leader().await.unwrap();
    let leader3 = node3.get_leader().await.unwrap();

    assert_eq!(leader1, leader2);
    assert_eq!(leader2, leader3);

    // Test distributed state
    let key = "shared_config";
    let value = serde_json::json!({
        "setting": "value",
        "number": 42
    });

    node1.set_state(key, value.clone()).await.unwrap();

    // Wait for replication
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify on all nodes
    let val1 = node1.get_state(key).await.unwrap();
    let val2 = node2.get_state(key).await.unwrap();
    let val3 = node3.get_state(key).await.unwrap();

    assert_eq!(val1, value);
    assert_eq!(val2, value);
    assert_eq!(val3, value);

    // Test partition tolerance
    node3.simulate_network_partition().await;

    // Update on majority partition
    let new_value = serde_json::json!({"setting": "updated"});
    node1.set_state(key, new_value.clone()).await.unwrap();

    // Heal partition
    node3.heal_network_partition().await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Node 3 should eventually get the update
    let val3_after = node3.get_state(key).await.unwrap();
    assert_eq!(val3_after, new_value);
}
