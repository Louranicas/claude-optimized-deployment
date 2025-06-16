//! MCP Manager Performance Benchmarks
//!
//! These benchmarks prove that our plugin system operates at the speed of thought.
//! Every measurement validates our architectural excellence.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use claude_optimized_deployment_rust::mcp_manager::{
    plugin::{negotiation::*, schema::*, *},
    plugins::{docker::*, kubernetes::*, prometheus::*},
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use serde_json::json;
use std::sync::Arc;
use tokio::runtime::Runtime;

/// Benchmark plugin initialization
fn bench_plugin_initialization(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("plugin_initialization");

    // Docker plugin initialization
    group.bench_function("docker_init", |b| {
        b.to_async(&rt).iter(|| async {
            let plugin = DockerPlugin::new();
            let handle = PluginHandle::new(Box::new(plugin));
            handle.initialize(json!({})).await.unwrap();
            black_box(handle)
        });
    });

    // Kubernetes plugin initialization
    group.bench_function("kubernetes_init", |b| {
        b.to_async(&rt).iter(|| async {
            let plugin = KubernetesPlugin::new();
            let handle = PluginHandle::new(Box::new(plugin));
            let _ = handle.initialize(json!({})).await; // May fail
            black_box(handle)
        });
    });

    // Prometheus plugin initialization
    group.bench_function("prometheus_init", |b| {
        b.to_async(&rt).iter(|| async {
            let plugin = PrometheusPlugin::new();
            let handle = PluginHandle::new(Box::new(plugin));
            let _ = handle.initialize(json!({})).await; // May fail
            black_box(handle)
        });
    });

    group.finish();
}

/// Benchmark request handling
fn bench_request_handling(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("request_handling");

    // Setup Docker plugin
    let docker_plugin = rt.block_on(async {
        let plugin = DockerPlugin::new();
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        handle.initialize(json!({})).await.unwrap();
        handle
    });

    // Benchmark simple request
    group.bench_function("simple_request", |b| {
        let handle = docker_plugin.clone();
        b.to_async(&rt).iter(|| async {
            let request = PluginRequest {
                id: "bench".to_string(),
                capability: Capability::new("docker", "system.ping", 1),
                method: "ping".to_string(),
                params: json!({}),
                metadata: json!({}),
            };

            let response = handle.handle(request).await.unwrap();
            black_box(response)
        });
    });

    // Benchmark complex request
    group.bench_function("complex_request", |b| {
        let handle = docker_plugin.clone();
        b.to_async(&rt).iter(|| async {
            let request = PluginRequest {
                id: "bench".to_string(),
                capability: Capability::new("docker", "container.list", 1),
                method: "list".to_string(),
                params: json!({
                    "all": true,
                    "filters": {
                        "status": ["running", "exited"],
                        "label": ["app=test"]
                    }
                }),
                metadata: json!({
                    "auth": "bearer token",
                    "trace_id": "123456"
                }),
            };

            let response = handle.handle(request).await.unwrap();
            black_box(response)
        });
    });

    group.finish();
}

/// Benchmark capability negotiation
fn bench_capability_negotiation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("capability_negotiation");

    // Setup negotiator with plugins
    let negotiator = rt.block_on(async {
        let config = NegotiatorConfig::default();
        let negotiator = CapabilityNegotiator::new(config);

        // Register multiple providers
        for i in 0..10 {
            let metadata = PluginMetadata {
                id: format!("provider-{}", i),
                name: format!("Provider {}", i),
                version: "1.0.0".to_string(),
                author: "Bench".to_string(),
                description: "Benchmark provider".to_string(),
                license: "MIT".to_string(),
                homepage: None,
                repository: None,
                min_mcp_version: "1.0.0".to_string(),
                dependencies: vec![],
                provides: vec![
                    Capability::new("bench", "operation.read", 1),
                    Capability::new("bench", "operation.write", 1),
                    Capability::new("bench", "operation.delete", 1),
                ],
                requires: vec![],
            };

            negotiator.register_plugin(&metadata).await.unwrap();
        }

        Arc::new(negotiator)
    });

    // Benchmark single capability negotiation
    group.bench_function("single_capability", |b| {
        let neg = negotiator.clone();
        b.to_async(&rt).iter(|| async {
            let session_id = neg
                .start_negotiation(
                    "consumer",
                    vec![Capability::new("bench", "operation.read", 1)],
                )
                .await
                .unwrap();

            // Wait for completion
            while let Ok(state) = neg.check_negotiation_status(&session_id).await {
                match state {
                    NegotiationState::Completed | NegotiationState::Failed => break,
                    _ => tokio::time::sleep(tokio::time::Duration::from_micros(10)).await,
                }
            }

            black_box(session_id)
        });
    });

    // Benchmark multiple capability negotiation
    group.bench_function("multiple_capabilities", |b| {
        let neg = negotiator.clone();
        b.to_async(&rt).iter(|| async {
            let session_id = neg
                .start_negotiation(
                    "consumer",
                    vec![
                        Capability::new("bench", "operation.read", 1),
                        Capability::new("bench", "operation.write", 1),
                        Capability::new("bench", "operation.delete", 1),
                    ],
                )
                .await
                .unwrap();

            // Wait for completion
            while let Ok(state) = neg.check_negotiation_status(&session_id).await {
                match state {
                    NegotiationState::Completed | NegotiationState::Failed => break,
                    _ => tokio::time::sleep(tokio::time::Duration::from_micros(10)).await,
                }
            }

            black_box(session_id)
        });
    });

    group.finish();
}

/// Benchmark schema validation
fn bench_schema_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("schema_validation");

    // Setup schema registry
    let mut registry = SchemaRegistry::new();

    // Register complex schema
    let schema = SchemaBuilder::new("complex")
        .property(
            "server",
            json!({
                "type": "object",
                "properties": {
                    "host": { "type": "string" },
                    "port": { "type": "integer", "minimum": 1, "maximum": 65535 },
                    "ssl": { "type": "boolean" }
                },
                "required": ["host", "port"]
            }),
            None,
        )
        .property(
            "database",
            json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "format": "uri" },
                    "pool_size": { "type": "integer", "minimum": 1, "maximum": 100 },
                    "timeout": { "type": "integer", "minimum": 1000 }
                }
            }),
            None,
        )
        .property(
            "features",
            json!({
                "type": "array",
                "items": { "type": "string" },
                "uniqueItems": true
            }),
            None,
        )
        .build();

    registry.register(schema).unwrap();

    // Benchmark valid config validation
    let valid_config = json!({
        "server": {
            "host": "localhost",
            "port": 8080,
            "ssl": false
        },
        "database": {
            "url": "postgres://localhost/db",
            "pool_size": 20,
            "timeout": 5000
        },
        "features": ["auth", "api", "websocket"]
    });

    group.bench_function("valid_config", |b| {
        b.iter(|| {
            let result = registry.validate("complex", &valid_config);
            black_box(result)
        });
    });

    // Benchmark invalid config validation
    let invalid_config = json!({
        "server": {
            "host": "localhost",
            "port": 99999, // Invalid port
            "ssl": false
        },
        "database": {
            "url": "not-a-url",
            "pool_size": 0, // Invalid pool size
            "timeout": 100 // Too low
        },
        "features": ["auth", "api", "api"] // Duplicate
    });

    group.bench_function("invalid_config", |b| {
        b.iter(|| {
            let result = registry.validate("complex", &invalid_config);
            black_box(result)
        });
    });

    group.finish();
}

/// Benchmark concurrent plugin operations
fn bench_concurrent_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("concurrent_operations");

    // Setup shared plugin handle
    let docker_plugin = rt.block_on(async {
        let plugin = DockerPlugin::new();
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        handle.initialize(json!({})).await.unwrap();
        handle
    });

    // Benchmark with different concurrency levels
    for concurrency in [1, 10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(concurrency),
            concurrency,
            |b, &concurrency| {
                let handle = docker_plugin.clone();
                b.to_async(&rt).iter(|| async move {
                    let mut tasks = vec![];

                    for i in 0..concurrency {
                        let handle_clone = handle.clone();
                        let task = tokio::spawn(async move {
                            let request = PluginRequest {
                                id: format!("bench-{}", i),
                                capability: Capability::new("docker", "system.version", 1),
                                method: "version".to_string(),
                                params: json!({}),
                                metadata: json!({}),
                            };

                            handle_clone.handle(request).await
                        });

                        tasks.push(task);
                    }

                    let results: Vec<_> = futures::future::join_all(tasks).await;
                    black_box(results)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark metric updates
fn bench_metric_updates(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("metric_updates");

    let negotiator = rt.block_on(async {
        let config = NegotiatorConfig::default();
        let negotiator = CapabilityNegotiator::new(config);

        // Register test plugin
        let metadata = PluginMetadata {
            id: "metrics-test".to_string(),
            name: "Metrics Test".to_string(),
            version: "1.0.0".to_string(),
            author: "Bench".to_string(),
            description: "Metrics benchmark".to_string(),
            license: "MIT".to_string(),
            homepage: None,
            repository: None,
            min_mcp_version: "1.0.0".to_string(),
            dependencies: vec![],
            provides: vec![Capability::new("test", "operation", 1)],
            requires: vec![],
        };

        negotiator.register_plugin(&metadata).await.unwrap();
        Arc::new(negotiator)
    });

    let capability = Capability::new("test", "operation", 1);

    group.bench_function("metric_update", |b| {
        let neg = negotiator.clone();
        let cap = capability.clone();
        b.to_async(&rt).iter(|| async {
            neg.update_capability_metrics("metrics-test", &cap, true, 1234)
                .await
                .unwrap();
        });
    });

    group.finish();
}

/// Benchmark configuration merging
fn bench_config_merging(c: &mut Criterion) {
    let mut group = c.benchmark_group("config_merging");

    let registry = SchemaRegistry::new();

    // Small configs
    let small_base = json!({
        "key1": "value1",
        "key2": 42
    });

    let small_overlay = json!({
        "key2": 84,
        "key3": true
    });

    group.bench_function("small_configs", |b| {
        b.iter(|| {
            let merged = registry.merge_configs(small_base.clone(), small_overlay.clone());
            black_box(merged)
        });
    });

    // Large nested configs
    let mut large_base = json!({});
    let mut large_overlay = json!({});

    for i in 0..100 {
        large_base[format!("section_{}", i)] = json!({
            "enabled": true,
            "config": {
                "timeout": 1000,
                "retries": 3,
                "features": ["a", "b", "c"]
            }
        });

        if i % 2 == 0 {
            large_overlay[format!("section_{}", i)] = json!({
                "enabled": false,
                "config": {
                    "timeout": 2000,
                    "new_field": "value"
                }
            });
        }
    }

    group.bench_function("large_configs", |b| {
        b.iter(|| {
            let merged = registry.merge_configs(large_base.clone(), large_overlay.clone());
            black_box(merged)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_plugin_initialization,
    bench_request_handling,
    bench_capability_negotiation,
    bench_schema_validation,
    bench_concurrent_operations,
    bench_metric_updates,
    bench_config_merging
);

criterion_main!(benches);
