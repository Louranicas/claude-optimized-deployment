//! Performance benchmarks for the orchestration engine
//!
//! Measures the performance of critical operations including:
//! - Service registration (target: sub-millisecond)
//! - Resource allocation
//! - Network port allocation
//! - Circuit breaker operations

use claude_optimized_deployment_rust::{
    network::{MeshConfig, PortAllocator, ServiceMesh},
    orchestrator::{
        DeploymentState, HealthStatus, NetworkConfig, Protocol, ResourceUsage, ServiceMetadata,
    },
    reliability::{CircuitBreaker, CircuitBreakerConfig},
    resources::{CpuManager, MemoryManager, ResourceManager, ResourceRequest, StorageManager},
    services::ServiceRegistry,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;
use tokio::runtime::Runtime;
use uuid::Uuid;

fn bench_service_registration(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("service_registration", |b| {
        let registry = ServiceRegistry::new();

        b.iter(|| {
            rt.block_on(async {
                let metadata = ServiceMetadata {
                    id: Uuid::new_v4(),
                    name: "bench-service".to_string(),
                    version: "1.0.0".to_string(),
                    state: DeploymentState::Pending,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                    health_status: HealthStatus::default(),
                    resource_usage: ResourceUsage::default(),
                    network_config: NetworkConfig {
                        internal_port: 8080,
                        external_port: None,
                        protocol: Protocol::Http,
                        service_mesh_enabled: false,
                        load_balancer_config: None,
                    },
                };

                black_box(registry.register_service(metadata).await.unwrap());
            });
        });
    });
}

fn bench_concurrent_registration(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("concurrent_registration");

    for num_services in [10, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_services),
            num_services,
            |b, &num_services| {
                let registry = ServiceRegistry::new();

                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = vec![];

                        for i in 0..num_services {
                            let registry_clone = &registry;
                            let handle = tokio::spawn(async move {
                                let metadata = ServiceMetadata {
                                    id: Uuid::new_v4(),
                                    name: format!("bench-service-{}", i),
                                    version: "1.0.0".to_string(),
                                    state: DeploymentState::Pending,
                                    created_at: chrono::Utc::now(),
                                    updated_at: chrono::Utc::now(),
                                    health_status: HealthStatus::default(),
                                    resource_usage: ResourceUsage::default(),
                                    network_config: NetworkConfig {
                                        internal_port: 8080 + i as u16,
                                        external_port: None,
                                        protocol: Protocol::Http,
                                        service_mesh_enabled: false,
                                        load_balancer_config: None,
                                    },
                                };

                                registry_clone.register_service(metadata).await
                            });
                            handles.push(handle);
                        }

                        for handle in handles {
                            black_box(handle.await.unwrap().unwrap());
                        }
                    });
                });
            },
        );
    }

    group.finish();
}

fn bench_resource_allocation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("resource_allocation", |b| {
        let manager = ResourceManager::new();

        b.iter(|| {
            rt.block_on(async {
                let service_id = Uuid::new_v4();
                let request = ResourceRequest {
                    cpu_cores: 1.0,
                    memory_mb: 512,
                    disk_mb: 1024,
                };

                let allocation = black_box(
                    manager
                        .allocate_resources(&service_id, request)
                        .await
                        .unwrap(),
                );

                // Clean up
                manager.release_resources(&service_id).await.unwrap();

                allocation
            });
        });
    });
}

fn bench_cpu_allocation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("cpu_allocation", |b| {
        let cpu_manager = CpuManager::new();

        b.iter(|| {
            rt.block_on(async {
                let service_id = Uuid::new_v4();
                let allocation = black_box(cpu_manager.allocate(&service_id, 2.0).await.unwrap());

                // Clean up
                cpu_manager.release(&service_id).await.unwrap();

                allocation
            });
        });
    });
}

fn bench_memory_allocation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("memory_allocation", |b| {
        let memory_manager = MemoryManager::new();

        b.iter(|| {
            rt.block_on(async {
                let service_id = Uuid::new_v4();
                let allocation =
                    black_box(memory_manager.allocate(&service_id, 1024).await.unwrap());

                // Clean up
                memory_manager.release(&service_id).await.unwrap();

                allocation
            });
        });
    });
}

fn bench_port_allocation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("port_allocation", |b| {
        let allocator = PortAllocator::new();

        b.iter(|| {
            rt.block_on(async {
                let service_id = Uuid::new_v4();
                let allocation = black_box(
                    allocator
                        .allocate_port(&service_id, Protocol::Http)
                        .await
                        .unwrap(),
                );

                // Clean up
                allocator.release_port(&service_id).await.unwrap();

                allocation
            });
        });
    });
}

fn bench_service_mesh_registration(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("service_mesh_registration", |b| {
        let mesh = ServiceMesh::new(MeshConfig::default());

        b.iter(|| {
            rt.block_on(async {
                let service_id = Uuid::new_v4();
                black_box(
                    mesh.register_service(&service_id, "bench-mesh-service".to_string())
                        .await
                        .unwrap(),
                );

                // Clean up
                mesh.deregister_service(&service_id).await.unwrap();
            });
        });
    });
}

fn bench_circuit_breaker(c: &mut Criterion) {
    let config = CircuitBreakerConfig {
        failure_threshold: 5,
        success_threshold: 2,
        timeout: Duration::from_secs(60),
        ..Default::default()
    };

    let breaker = CircuitBreaker::new(config);

    c.bench_function("circuit_breaker_success", |b| {
        b.iter(|| {
            if black_box(breaker.can_proceed()) {
                breaker.record_success();
            }
        });
    });

    c.bench_function("circuit_breaker_failure", |b| {
        b.iter(|| {
            if black_box(breaker.can_proceed()) {
                breaker.record_failure();
            }
        });
    });
}

fn bench_service_lookup(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("service_lookup", |b| {
        let registry = ServiceRegistry::new();

        // Pre-populate registry
        rt.block_on(async {
            for i in 0..1000 {
                let metadata = ServiceMetadata {
                    id: Uuid::new_v4(),
                    name: format!("service-{}", i),
                    version: "1.0.0".to_string(),
                    state: DeploymentState::Running,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                    health_status: HealthStatus::default(),
                    resource_usage: ResourceUsage::default(),
                    network_config: NetworkConfig {
                        internal_port: 8080 + i as u16,
                        external_port: None,
                        protocol: Protocol::Http,
                        service_mesh_enabled: false,
                        load_balancer_config: None,
                    },
                };
                registry.register_service(metadata).await.unwrap();
            }
        });

        // Benchmark lookups
        b.iter(|| {
            rt.block_on(async {
                let service_id = Uuid::new_v4(); // Will fail, but tests lookup performance
                let _ = black_box(registry.get_service(service_id).await);
            });
        });
    });
}

criterion_group!(
    benches,
    bench_service_registration,
    bench_concurrent_registration,
    bench_resource_allocation,
    bench_cpu_allocation,
    bench_memory_allocation,
    bench_port_allocation,
    bench_service_mesh_registration,
    bench_circuit_breaker,
    bench_service_lookup,
);

criterion_main!(benches);
