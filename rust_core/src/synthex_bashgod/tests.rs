//! Comprehensive tests for SYNTHEX-BashGod
//!
//! Tests cover unit, integration, and performance aspects

use super::*;
use tokio::test;

#[cfg(test)]
mod unit_tests {
    use super::*;
    
    #[test]
    fn test_bash_command_creation() {
        let cmd = BashCommand {
            id: "test-1".to_string(),
            command: "echo".to_string(),
            args: vec!["hello".to_string()],
            env: HashMap::new(),
            working_dir: None,
            resources: ResourceEstimate::default(),
        };
        
        assert_eq!(cmd.command, "echo");
        assert_eq!(cmd.args.len(), 1);
    }
    
    #[test]
    fn test_command_chain_builder() {
        let chain = CommandChain {
            id: "chain-1".to_string(),
            commands: vec![
                BashCommand {
                    id: "cmd-1".to_string(),
                    command: "find".to_string(),
                    args: vec![".".to_string(), "-name".to_string(), "*.log".to_string()],
                    env: HashMap::new(),
                    working_dir: None,
                    resources: ResourceEstimate::default(),
                },
                BashCommand {
                    id: "cmd-2".to_string(),
                    command: "grep".to_string(),
                    args: vec!["ERROR".to_string()],
                    env: HashMap::new(),
                    working_dir: None,
                    resources: ResourceEstimate::default(),
                },
            ],
            dependencies: HashMap::new(),
            strategy: ExecutionStrategy::Sequential,
            metadata: ChainMetadata {
                intent: "Find error logs".to_string(),
                tags: vec!["logging".to_string(), "debugging".to_string()],
                performance_history: vec![],
                created_by: "test".to_string(),
                created_at: chrono::Utc::now(),
            },
        };
        
        assert_eq!(chain.commands.len(), 2);
        assert_eq!(chain.metadata.intent, "Find error logs");
    }
    
    #[test]
    fn test_resource_requirements() {
        let resources = ResourceEstimate {
            cpu_cores: Some(2.0),
            memory_mb: Some(1024),
            disk_mb: Some(500),
            network_mbps: Some(100.0),
            gpu: false,
        };
        
        assert_eq!(resources.cpu_cores, Some(2.0));
        assert_eq!(resources.memory_mb, Some(1024));
        assert!(!resources.gpu);
    }
    
    #[test]
    fn test_execution_strategy_serialization() {
        let strategies = vec![
            ExecutionStrategy::Sequential,
            ExecutionStrategy::Parallel { max_concurrent: 4 },
            ExecutionStrategy::Optimized,
            ExecutionStrategy::Predictive,
        ];
        
        for strategy in strategies {
            let serialized = serde_json::to_string(&strategy).unwrap();
            let deserialized: ExecutionStrategy = serde_json::from_str(&serialized).unwrap();
            assert_eq!(format!("{:?}", strategy), format!("{:?}", deserialized));
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use service::BashGodServiceImpl;
    
    #[tokio::test]
    async fn test_service_creation() {
        let config = BashGodConfig::default();
        let service = BashGodServiceImpl::new(config).await;
        assert!(service.is_ok());
    }
    
    #[tokio::test]
    async fn test_simple_command_execution() {
        let config = BashGodConfig::default();
        let service = create_bashgod_service(config).await.unwrap();
        
        let chain = CommandChain {
            id: "test-chain".to_string(),
            commands: vec![
                BashCommand {
                    id: "echo-test".to_string(),
                    command: "echo".to_string(),
                    args: vec!["Hello, SYNTHEX-BashGod!".to_string()],
                    env: HashMap::new(),
                    working_dir: None,
                    resources: ResourceEstimate::default(),
                },
            ],
            dependencies: HashMap::new(),
            strategy: ExecutionStrategy::Sequential,
            metadata: ChainMetadata {
                intent: "Test echo".to_string(),
                tags: vec![],
                performance_history: vec![],
                created_by: "test".to_string(),
                created_at: chrono::Utc::now(),
            },
        };
        
        let result = service.execute_chain(chain).await;
        assert!(result.is_ok());
        
        let chain_result = result.unwrap();
        assert!(chain_result.success);
        assert_eq!(chain_result.command_results.len(), 1);
    }
    
    #[tokio::test]
    async fn test_chain_optimization() {
        let service = create_bashgod_service(BashGodConfig::default()).await.unwrap();
        
        let chain = CommandChain {
            id: "optimize-test".to_string(),
            commands: vec![
                BashCommand {
                    id: "find-1".to_string(),
                    command: "find".to_string(),
                    args: vec![".".to_string(), "-name".to_string(), "*.txt".to_string()],
                    env: HashMap::new(),
                    working_dir: None,
                    resources: ResourceEstimate::default(),
                },
                BashCommand {
                    id: "grep-1".to_string(),
                    command: "grep".to_string(),
                    args: vec!["pattern".to_string()],
                    env: HashMap::new(),
                    working_dir: None,
                    resources: ResourceEstimate::default(),
                },
            ],
            dependencies: HashMap::new(),
            strategy: ExecutionStrategy::Sequential,
            metadata: ChainMetadata {
                intent: "Find and grep".to_string(),
                tags: vec![],
                performance_history: vec![],
                created_by: "test".to_string(),
                created_at: chrono::Utc::now(),
            },
        };
        
        let optimized = service.optimize_chain(&chain).await;
        assert!(optimized.is_ok());
    }
    
    #[tokio::test]
    async fn test_learning_insights() {
        let service = create_bashgod_service(BashGodConfig::default()).await.unwrap();
        
        let insights = service.get_insights().await;
        assert!(insights.is_ok());
        
        // Initially should be empty
        assert_eq!(insights.unwrap().len(), 0);
    }
}

#[cfg(test)]
mod memory_tests {
    use super::*;
    use memory::{MemorySystem, TensorMemory, GraphMemory, HybridMemory};
    
    #[tokio::test]
    async fn test_tensor_memory() {
        let memory = TensorMemory::new(1024, 64);
        
        let pattern = vec![1.0, 2.0, 3.0, 4.0];
        let pattern_id = "test-pattern";
        
        let stored = memory.store_pattern(pattern_id, pattern.clone()).await;
        assert!(stored.is_ok());
        
        let similar = memory.find_similar(&pattern, 5).await;
        assert!(similar.is_ok());
        assert!(!similar.unwrap().is_empty());
    }
    
    #[tokio::test]
    async fn test_graph_memory() {
        let memory = GraphMemory::new();
        
        // Add nodes
        memory.add_command_node("cmd1", &BashCommand {
            id: "cmd1".to_string(),
            command: "echo".to_string(),
            args: vec!["test".to_string()],
            env: HashMap::new(),
            working_dir: None,
            resources: ResourceEstimate::default(),
        }).await.unwrap();
        
        memory.add_command_node("cmd2", &BashCommand {
            id: "cmd2".to_string(),
            command: "grep".to_string(),
            args: vec!["pattern".to_string()],
            env: HashMap::new(),
            working_dir: None,
            resources: ResourceEstimate::default(),
        }).await.unwrap();
        
        // Add dependency
        memory.add_dependency("cmd1", "cmd2").await.unwrap();
        
        // Find dependencies
        let deps = memory.find_dependencies("cmd1").await.unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0], "cmd2");
    }
    
    #[tokio::test]
    async fn test_hybrid_memory() {
        let config = memory::MemoryConfig {
            tensor_size: 512,
            tensor_dim: 32,
            graph_max_nodes: 1000,
            hybrid_weights: memory::HybridWeights {
                tensor_weight: 0.6,
                graph_weight: 0.4,
            },
        };
        
        let memory = HybridMemory::new(config);
        
        let cmd = BashCommand {
            id: "test-cmd".to_string(),
            command: "ls".to_string(),
            args: vec!["-la".to_string()],
            env: HashMap::new(),
            working_dir: None,
            resources: ResourceEstimate::default(),
        };
        
        let stored = memory.store(&cmd).await;
        assert!(stored.is_ok());
        
        let similar = memory.find_similar(&cmd, 3).await;
        assert!(similar.is_ok());
    }
}

#[cfg(test)]
mod synergy_tests {
    use super::*;
    use synergy::{SynergyDetector, SynergyOptimizer};
    
    #[tokio::test]
    async fn test_pipeline_synergy_detection() {
        let detector = SynergyDetector::new(Default::default());
        
        let commands = vec![
            "find . -name '*.log'".to_string(),
            "grep ERROR".to_string(),
            "sort".to_string(),
            "uniq -c".to_string(),
        ];
        
        let context = synergy::SynergyContext {
            resources: synergy::SystemResources {
                cpu_cores: 4,
                memory_mb: 8192,
                has_shm: true,
                has_fifo: true,
            },
            available_tools: vec!["find".to_string(), "grep".to_string()],
            constraints: synergy::PerformanceConstraints {
                max_time_ms: None,
                max_memory_mb: None,
                atomic_required: false,
            },
        };
        
        let synergies = detector.detect(&commands, &context).await.unwrap();
        assert!(!synergies.is_empty());
        
        // Should detect pipeline synergy
        let pipeline_synergy = synergies.iter()
            .find(|s| matches!(s.synergy_type, synergy::SynergyType::DataPipeline))
            .expect("Should find pipeline synergy");
        
        assert!(pipeline_synergy.score > 0.5);
    }
    
    #[tokio::test]
    async fn test_synergy_optimization() {
        let optimizer = SynergyOptimizer::new(Default::default());
        
        let commands = vec![
            "cat file.txt".to_string(),
            "grep pattern".to_string(),
            "wc -l".to_string(),
        ];
        
        let synergy = synergy::CommandSynergy {
            id: "test-synergy".to_string(),
            commands: vec![0, 1, 2],
            synergy_type: synergy::SynergyType::DataPipeline,
            score: 0.8,
            description: "Pipeline optimization".to_string(),
            benefits: synergy::SynergyBenefits {
                performance_gain: 0.4,
                resource_savings: 0.3,
                complexity_reduction: 0.2,
                reliability_gain: 0.1,
            },
            implementation: synergy::SynergyImplementation {
                strategy: synergy::ImplementationStrategy::PipelineMerge,
                changes: vec![],
                prerequisites: vec![],
                example: None,
            },
        };
        
        let context = synergy::SynergyContext {
            resources: synergy::SystemResources {
                cpu_cores: 4,
                memory_mb: 8192,
                has_shm: true,
                has_fifo: true,
            },
            available_tools: vec!["grep".to_string(), "wc".to_string()],
            constraints: synergy::PerformanceConstraints {
                max_time_ms: None,
                max_memory_mb: None,
                atomic_required: false,
            },
        };
        
        let result = optimizer.optimize(commands, vec![synergy], &context).await.unwrap();
        assert!(result.success);
        assert_eq!(result.optimized.len(), 1); // Should merge into single pipeline
        assert!(result.optimized[0].contains("|"));
    }
}

#[cfg(test)]
mod mcp_integration_tests {
    use super::*;
    use mcp_integration::{ToolEnhancer, MCPTool, EnhancedCommand};
    
    #[tokio::test]
    async fn test_docker_command_enhancement() {
        let enhancer = ToolEnhancer::new(vec![]);
        
        let cmd = BashCommand {
            id: "docker-ps".to_string(),
            command: "docker ps -a".to_string(),
            args: vec![],
            env: HashMap::new(),
            working_dir: None,
            resources: ResourceEstimate::default(),
        };
        
        let can_enhance = enhancer.can_enhance(&cmd).await;
        assert!(can_enhance);
        
        let config = mcp_integration::MCPConfig {
            default_strategy: mcp_integration::ExecutionStrategy::MCPFirst,
            performance_thresholds: mcp_integration::PerformanceThresholds {
                min_speedup: 1.2,
                min_efficiency: 1.1,
                max_latency_ms: 5000,
            },
            enable_caching: true,
            cache_ttl: 300,
        };
        
        let enhanced = enhancer.enhance(&cmd, &config).await.unwrap();
        assert!(enhanced.mcp_tool.is_some());
        assert!(enhanced.performance_estimate.speedup > 1.0);
    }
    
    #[tokio::test]
    async fn test_capability_mapping() {
        let mapper = mcp_integration::CapabilityMapper::new();
        
        // Test Docker mapping
        let caps = mapper.map_command("docker ps");
        assert!(!caps.is_empty());
        assert_eq!(caps[0].server, mcp_integration::ServerType::Docker);
        
        // Test Kubernetes mapping
        let caps = mapper.map_command("kubectl get pods");
        assert!(!caps.is_empty());
        assert_eq!(caps[0].server, mcp_integration::ServerType::Kubernetes);
        
        // Test Git mapping
        let caps = mapper.map_command("git status");
        assert!(!caps.is_empty());
        assert_eq!(caps[0].server, mcp_integration::ServerType::Git);
    }
}

#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;
    
    #[tokio::test]
    async fn test_concurrent_execution_performance() {
        let service = create_bashgod_service(BashGodConfig {
            executor_pool_size: 8,
            ..Default::default()
        }).await.unwrap();
        
        // Create chain with multiple independent commands
        let mut commands = Vec::new();
        for i in 0..10 {
            commands.push(BashCommand {
                id: format!("cmd-{}", i),
                command: "echo".to_string(),
                args: vec![format!("test-{}", i)],
                env: HashMap::new(),
                working_dir: None,
                resources: ResourceEstimate::default(),
            });
        }
        
        let chain = CommandChain {
            id: "perf-test".to_string(),
            commands,
            dependencies: HashMap::new(),
            strategy: ExecutionStrategy::Parallel { max_concurrent: 8 },
            metadata: ChainMetadata {
                intent: "Performance test".to_string(),
                tags: vec![],
                performance_history: vec![],
                created_by: "test".to_string(),
                created_at: chrono::Utc::now(),
            },
        };
        
        let start = Instant::now();
        let result = service.execute_chain(chain).await.unwrap();
        let duration = start.elapsed();
        
        assert!(result.success);
        assert_eq!(result.command_results.len(), 10);
        
        // Parallel execution should be faster than sequential
        assert!(duration.as_millis() < 1000); // Should complete in under 1 second
    }
    
    #[tokio::test]
    async fn test_memory_performance() {
        let memory = memory::TensorMemory::new(10000, 128);
        
        let start = Instant::now();
        
        // Store many patterns
        for i in 0..1000 {
            let pattern: Vec<f32> = (0..128).map(|j| (i * j) as f32).collect();
            memory.store_pattern(&format!("pattern-{}", i), pattern).await.unwrap();
        }
        
        let store_duration = start.elapsed();
        
        // Search for similar patterns
        let search_pattern: Vec<f32> = (0..128).map(|j| j as f32 * 500.0).collect();
        let search_start = Instant::now();
        let similar = memory.find_similar(&search_pattern, 10).await.unwrap();
        let search_duration = search_start.elapsed();
        
        assert_eq!(similar.len(), 10);
        assert!(store_duration.as_millis() < 5000); // Should store 1000 patterns in < 5s
        assert!(search_duration.as_millis() < 100); // Should search in < 100ms
    }
}

#[cfg(test)]
mod error_handling_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_invalid_command_handling() {
        let service = create_bashgod_service(BashGodConfig::default()).await.unwrap();
        
        let chain = CommandChain {
            id: "error-test".to_string(),
            commands: vec![
                BashCommand {
                    id: "invalid-cmd".to_string(),
                    command: "this_command_does_not_exist".to_string(),
                    args: vec![],
                    env: HashMap::new(),
                    working_dir: None,
                    resources: ResourceEstimate::default(),
                },
            ],
            dependencies: HashMap::new(),
            strategy: ExecutionStrategy::Sequential,
            metadata: ChainMetadata {
                intent: "Error test".to_string(),
                tags: vec![],
                performance_history: vec![],
                created_by: "test".to_string(),
                created_at: chrono::Utc::now(),
            },
        };
        
        let result = service.execute_chain(chain).await;
        assert!(result.is_err() || !result.unwrap().success);
    }
    
    #[tokio::test]
    async fn test_resource_limit_enforcement() {
        let service = create_bashgod_service(BashGodConfig::default()).await.unwrap();
        
        let chain = CommandChain {
            id: "resource-test".to_string(),
            commands: vec![
                BashCommand {
                    id: "resource-heavy".to_string(),
                    command: "sleep".to_string(),
                    args: vec!["60".to_string()], // 60 second sleep
                    env: HashMap::new(),
                    working_dir: None,
                    resources: ResourceEstimate {
                        cpu_cores: Some(100.0), // Impossible requirement
                        memory_mb: Some(1000000), // 1TB memory
                        disk_mb: None,
                        network_mbps: None,
                        gpu: true,
                    },
                },
            ],
            dependencies: HashMap::new(),
            strategy: ExecutionStrategy::Sequential,
            metadata: ChainMetadata {
                intent: "Resource limit test".to_string(),
                tags: vec![],
                performance_history: vec![],
                created_by: "test".to_string(),
                created_at: chrono::Utc::now(),
            },
        };
        
        let result = service.execute_chain(chain).await;
        // Should either fail or handle gracefully
        assert!(result.is_err() || !result.unwrap().success);
    }
}