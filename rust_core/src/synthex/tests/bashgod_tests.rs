//! Tests for SYNTHEX BashGod optimizer and ML components

#[cfg(test)]
mod tests {
    use crate::synthex::{
        bashgod_optimizer::{BashGodOptimizer, OptimizationStrategy},
        performance_optimizer::MLOptimizer,
    };
    
    #[tokio::test]
    async fn test_bashgod_initialization() {
        let optimizer = BashGodOptimizer::new();
        
        assert!(optimizer.is_ready());
        assert_eq!(optimizer.get_strategy(), OptimizationStrategy::Balanced);
    }
    
    #[tokio::test]
    async fn test_command_pattern_detection() {
        let optimizer = BashGodOptimizer::new();
        
        // Feed command history
        let commands = vec![
            "git add .",
            "git commit -m 'test'",
            "git push",
            "git add .",
            "git commit -m 'another test'",
            "git push",
        ];
        
        for cmd in &commands {
            optimizer.record_command(cmd).await;
        }
        
        // Should detect git workflow pattern
        let patterns = optimizer.detect_patterns().await;
        assert!(!patterns.is_empty());
        
        let git_pattern = patterns.iter()
            .find(|p| p.name == "git_workflow")
            .expect("Git pattern not detected");
            
        assert_eq!(git_pattern.frequency, 2);
        assert!(git_pattern.confidence > 0.8);
    }
    
    #[tokio::test]
    async fn test_command_prediction() {
        let optimizer = BashGodOptimizer::new();
        
        // Train on historical data
        let history = vec![
            ("make", "test"),
            ("make", "build"),
            ("make", "deploy"),
            ("cargo", "build"),
            ("cargo", "test"),
            ("cargo", "run"),
        ];
        
        for (prefix, completion) in &history {
            optimizer.train_prediction(prefix, completion).await;
        }
        
        // Test predictions
        let make_predictions = optimizer.predict_next("make").await;
        assert!(make_predictions.contains(&"test".to_string()));
        assert!(make_predictions.contains(&"build".to_string()));
        
        let cargo_predictions = optimizer.predict_next("cargo").await;
        assert!(cargo_predictions.contains(&"build".to_string()));
        assert!(cargo_predictions.contains(&"test".to_string()));
    }
    
    #[tokio::test]
    async fn test_optimization_strategies() {
        let mut optimizer = BashGodOptimizer::new();
        
        // Test different strategies
        optimizer.set_strategy(OptimizationStrategy::Speed);
        let speed_config = optimizer.optimize_for_current_workload().await;
        assert!(speed_config.parallel_execution);
        assert!(speed_config.cache_enabled);
        
        optimizer.set_strategy(OptimizationStrategy::Memory);
        let memory_config = optimizer.optimize_for_current_workload().await;
        assert!(!memory_config.enable_gpu_acceleration);
        assert!(memory_config.memory_limit_mb < 1000);
        
        optimizer.set_strategy(OptimizationStrategy::Accuracy);
        let accuracy_config = optimizer.optimize_for_current_workload().await;
        assert!(accuracy_config.max_retries > 3);
        assert!(accuracy_config.timeout_seconds > 30);
    }
    
    #[tokio::test]
    #[cfg(feature = "ml")]
    async fn test_ml_optimization() {
        let ml_optimizer = MLOptimizer::new();
        
        // Generate training data
        let mut training_data = vec![];
        for i in 0..100 {
            let features = vec![
                i as f32 / 100.0,  // Query complexity
                (i % 10) as f32,   // Agent count
                if i % 2 == 0 { 1.0 } else { 0.0 }, // Parallel enabled
            ];
            let performance = if i % 2 == 0 { 0.9 } else { 0.5 };
            
            training_data.push((features, performance));
        }
        
        // Train model
        ml_optimizer.train(&training_data).await.unwrap();
        
        // Test predictions
        let test_features = vec![0.5, 5.0, 1.0];
        let prediction = ml_optimizer.predict(&test_features).await.unwrap();
        
        assert!(prediction > 0.7); // Should predict good performance
    }
    
    #[tokio::test]
    async fn test_adaptive_learning() {
        let optimizer = BashGodOptimizer::new();
        
        // Simulate changing workload patterns
        for epoch in 0..3 {
            let pattern = match epoch {
                0 => vec!["search", "analyze", "report"],
                1 => vec!["compile", "test", "deploy"],
                2 => vec!["backup", "restore", "verify"],
                _ => vec![],
            };
            
            for _ in 0..10 {
                for cmd in &pattern {
                    optimizer.record_command(cmd).await;
                }
            }
            
            // Optimizer should adapt to new pattern
            let config = optimizer.optimize_for_current_workload().await;
            println!("Epoch {} optimization: {:?}", epoch, config);
            
            // Verify adaptation
            let patterns = optimizer.detect_patterns().await;
            let dominant_pattern = patterns.iter()
                .max_by_key(|p| p.frequency)
                .expect("No patterns detected");
                
            assert!(dominant_pattern.commands.iter().any(|c| pattern.contains(&c.as_str())));
        }
    }
    
    #[tokio::test]
    async fn test_resource_prediction() {
        let optimizer = BashGodOptimizer::new();
        
        // Record resource usage for different query types
        let usage_data = vec![
            ("simple search", 10, 100),      // CPU%, Memory MB
            ("complex aggregation", 80, 500),
            ("parallel processing", 90, 800),
            ("simple search", 12, 110),
            ("complex aggregation", 85, 520),
        ];
        
        for (query_type, cpu, memory) in &usage_data {
            optimizer.record_resource_usage(query_type, *cpu, *memory).await;
        }
        
        // Predict resource needs
        let simple_prediction = optimizer.predict_resource_usage("simple search").await;
        assert!(simple_prediction.cpu < 20);
        assert!(simple_prediction.memory < 200);
        
        let complex_prediction = optimizer.predict_resource_usage("complex aggregation").await;
        assert!(complex_prediction.cpu > 70);
        assert!(complex_prediction.memory > 400);
    }
    
    #[tokio::test]
    async fn test_anomaly_detection() {
        let optimizer = BashGodOptimizer::new();
        
        // Normal pattern
        for _ in 0..50 {
            optimizer.record_performance_metric("latency", 50.0).await;
        }
        
        // Anomalies
        optimizer.record_performance_metric("latency", 500.0).await;
        optimizer.record_performance_metric("latency", 5.0).await;
        
        let anomalies = optimizer.detect_anomalies("latency").await;
        assert_eq!(anomalies.len(), 2);
        assert!(anomalies.iter().any(|a| a.value > 400.0));
        assert!(anomalies.iter().any(|a| a.value < 10.0));
    }
    
    #[tokio::test]
    async fn test_auto_tuning() {
        let optimizer = BashGodOptimizer::new();
        
        // Simulate performance feedback loop
        let mut current_config = crate::synthex::config::SynthexConfig {
            max_concurrent_agents: 5,
            cache_size: 100,
            timeout_seconds: 10,
            enable_ml_optimization: false,
            enable_gpu_acceleration: false,
            max_retries: 3,
            batch_size: 10,
            memory_limit_mb: 512,
        };
        
        for iteration in 0..5 {
            // Measure performance with current config
            let performance = match iteration {
                0 => 0.5,  // Initial poor performance
                1 => 0.6,  // Some improvement
                2 => 0.75, // Better
                3 => 0.85, // Good
                4 => 0.9,  // Excellent
                _ => 0.0,
            };
            
            optimizer.record_config_performance(&current_config, performance).await;
            
            // Get tuned config
            let new_config = optimizer.auto_tune(&current_config).await;
            
            // Verify progressive improvement
            if iteration > 0 {
                assert!(
                    new_config.max_concurrent_agents >= current_config.max_concurrent_agents ||
                    new_config.cache_size >= current_config.cache_size
                );
            }
            
            current_config = new_config;
        }
        
        // Final config should be optimized
        assert!(current_config.max_concurrent_agents > 5);
        assert!(current_config.cache_size > 100);
    }
    
    #[tokio::test]
    async fn test_workload_classification() {
        let optimizer = BashGodOptimizer::new();
        
        // Different workload types
        let workloads = vec![
            ("batch processing", vec!["process file1", "process file2", "aggregate results"]),
            ("interactive queries", vec!["search user", "get details", "update record"]),
            ("analytical workload", vec!["calculate metrics", "generate report", "visualize data"]),
        ];
        
        for (workload_type, commands) in &workloads {
            for cmd in commands {
                optimizer.record_command_with_context(cmd, workload_type).await;
            }
        }
        
        // Test classification
        let batch_class = optimizer.classify_workload(&["process file3", "aggregate data"]).await;
        assert_eq!(batch_class, "batch processing");
        
        let interactive_class = optimizer.classify_workload(&["search product", "get price"]).await;
        assert_eq!(interactive_class, "interactive queries");
    }
}