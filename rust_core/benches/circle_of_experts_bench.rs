// ============================================================================
// CIRCLE OF EXPERTS BENCHMARKS
// ============================================================================
// Performance benchmarks for the Circle of Experts Rust implementation,
// measuring speed improvements over Python for various operations.
// ============================================================================

use code_rust_core::circle_of_experts::{
    CircleConfig, ExpertResponse, SimilarityAlgorithm, process_expert_responses,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use std::collections::HashMap;
use std::sync::Arc;

/// Generate sample expert responses for benchmarking
fn generate_expert_responses(count: usize, response_length: usize) -> Vec<ExpertResponse> {
    (0..count)
        .map(|i| {
            let content = format!(
                "Expert {}: {}",
                i,
                (0..response_length)
                    .map(|_| "This is a sample expert response with meaningful content. ")
                    .collect::<String>()
            );
            
            ExpertResponse {
                expert_name: format!("Expert{}", i),
                content,
                confidence: 0.7 + (i as f32 % 3) * 0.1,
                metadata: HashMap::new(),
                timestamp: 1234567890 + i as u64,
            }
        })
        .collect()
}

/// Benchmark consensus computation with different numbers of experts
fn bench_consensus_computation(c: &mut Criterion) {
    let mut group = c.benchmark_group("consensus_computation");
    
    for expert_count in [5, 10, 20, 50].iter() {
        let responses = generate_expert_responses(*expert_count, 50);
        let config = Arc::new(CircleConfig {
            enable_parallel_processing: true,
            ..Default::default()
        });
        
        group.throughput(Throughput::Elements(*expert_count as u64));
        group.bench_with_input(
            BenchmarkId::new("parallel", expert_count),
            expert_count,
            |b, _| {
                b.iter(|| {
                    process_expert_responses(black_box(responses.clone()), black_box(config.clone()))
                });
            },
        );
        
        let config_sequential = Arc::new(CircleConfig {
            enable_parallel_processing: false,
            ..Default::default()
        });
        
        group.bench_with_input(
            BenchmarkId::new("sequential", expert_count),
            expert_count,
            |b, _| {
                b.iter(|| {
                    process_expert_responses(black_box(responses.clone()), black_box(config_sequential.clone()))
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark different similarity algorithms
fn bench_similarity_algorithms(c: &mut Criterion) {
    let mut group = c.benchmark_group("similarity_algorithms");
    let responses = generate_expert_responses(20, 100);
    
    for algorithm in [
        SimilarityAlgorithm::Cosine,
        SimilarityAlgorithm::Jaccard,
        SimilarityAlgorithm::LevenshteinNormalized,
    ] {
        let config = Arc::new(CircleConfig {
            similarity_algorithm: algorithm,
            enable_parallel_processing: true,
            ..Default::default()
        });
        
        group.bench_with_input(
            BenchmarkId::new("algorithm", format!("{:?}", algorithm)),
            &algorithm,
            |b, _| {
                b.iter(|| {
                    process_expert_responses(black_box(responses.clone()), black_box(config.clone()))
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark response aggregation with varying response sizes
fn bench_response_aggregation(c: &mut Criterion) {
    let mut group = c.benchmark_group("response_aggregation");
    
    for response_length in [10, 50, 100, 500].iter() {
        let responses = generate_expert_responses(10, *response_length);
        let config = Arc::new(CircleConfig::default());
        
        group.throughput(Throughput::Bytes((*response_length * 10) as u64));
        group.bench_with_input(
            BenchmarkId::new("response_length", response_length),
            response_length,
            |b, _| {
                b.iter(|| {
                    process_expert_responses(black_box(responses.clone()), black_box(config.clone()))
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark pattern analysis scalability
fn bench_pattern_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("pattern_analysis");
    
    // Test with different numbers of unique patterns
    for pattern_complexity in [10, 50, 100, 200].iter() {
        let responses: Vec<ExpertResponse> = (0..20)
            .map(|i| {
                let content = (0..*pattern_complexity)
                    .map(|j| format!("Pattern{} ", j % (*pattern_complexity / 2)))
                    .collect::<String>();
                
                ExpertResponse {
                    expert_name: format!("Expert{}", i),
                    content,
                    confidence: 0.8,
                    metadata: HashMap::new(),
                    timestamp: 1234567890,
                }
            })
            .collect();
        
        let config = Arc::new(CircleConfig::default());
        
        group.bench_with_input(
            BenchmarkId::new("pattern_complexity", pattern_complexity),
            pattern_complexity,
            |b, _| {
                b.iter(|| {
                    process_expert_responses(black_box(responses.clone()), black_box(config.clone()))
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark thread scaling efficiency
fn bench_thread_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("thread_scaling");
    let responses = generate_expert_responses(50, 100);
    
    for thread_count in [1, 2, 4, 8].iter() {
        let config = Arc::new(CircleConfig {
            enable_parallel_processing: true,
            max_threads: Some(*thread_count),
            ..Default::default()
        });
        
        group.bench_with_input(
            BenchmarkId::new("threads", thread_count),
            thread_count,
            |b, _| {
                // Set thread pool size
                rayon::ThreadPoolBuilder::new()
                    .num_threads(*thread_count)
                    .build()
                    .unwrap()
                    .install(|| {
                        b.iter(|| {
                            process_expert_responses(black_box(responses.clone()), black_box(config.clone()))
                        });
                    });
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_consensus_computation,
    bench_similarity_algorithms,
    bench_response_aggregation,
    bench_pattern_analysis,
    bench_thread_scaling
);
criterion_main!(benches);