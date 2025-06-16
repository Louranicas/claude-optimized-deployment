use quality_mcp_server::{QualityMCPServer, CodeChanges, FileChange};
use std::env;
use tokio::signal;
use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting Quality MCP Server");
    info!("Memory allocation: 2GB for testing intelligence");

    // Create the server
    let server = QualityMCPServer::new().await?;
    info!("Quality MCP Server initialized successfully");

    // Example usage - demonstrate core features
    demo_core_features(&server).await?;

    // Start the server (this would typically be an MCP server loop)
    info!("Quality MCP Server running. Press Ctrl+C to stop.");
    
    // Wait for shutdown signal
    signal::ctrl_c().await?;
    info!("Shutdown signal received. Stopping Quality MCP Server...");

    Ok(())
}

async fn demo_core_features(server: &QualityMCPServer) -> Result<(), Box<dyn std::error::Error>> {
    info!("Demonstrating Quality MCP Server features...");

    // Demo 1: Test Suite Optimization
    info!("\n1. Testing smart test suite optimization...");
    let code_changes = CodeChanges {
        files: vec![
            FileChange {
                path: "src/auth/user.rs".to_string(),
                additions: vec![
                    "pub fn validate_user(user: &User) -> bool {".to_string(),
                    "    user.is_active && !user.email.is_empty()".to_string(),
                    "}".to_string(),
                ],
                deletions: vec![
                    "fn old_validate(user: &User) -> bool {".to_string(),
                ],
                modifications: vec![
                    "user.email = user.email.trim().to_lowercase();".to_string(),
                ],
            },
            FileChange {
                path: "src/core/database.rs".to_string(),
                additions: vec![
                    "pub async fn migrate_schema() -> Result<(), Error> {".to_string(),
                ],
                deletions: vec![],
                modifications: vec![
                    "connection_timeout: Duration::from_secs(30)".to_string(),
                ],
            },
        ],
        commit_hash: "abc123def456789".to_string(),
        timestamp: chrono::Utc::now(),
    };

    match server.optimize_test_suite(code_changes).await {
        Ok(test_suite) => {
            info!("✅ Test suite optimization successful!");
            info!("  Optimized tests: {}", test_suite.tests.len());
            info!("  Strategy: {}", test_suite.optimization_strategy);
            info!("  Estimated duration: {:?}", test_suite.estimated_duration);
            
            for (i, test) in test_suite.tests.iter().take(5).enumerate() {
                info!("  Test {}: {} (priority: {:.2}, failure_prob: {:.2})", 
                      i + 1, test.name, test.priority, test.failure_probability);
            }
        }
        Err(e) => error!("❌ Test suite optimization failed: {}", e),
    }

    // Demo 2: Quality Issue Prediction
    info!("\n2. Testing quality issue prediction...");
    let sample_code = r#"
pub fn complex_function(input: &str, config: Config, options: Vec<String>) -> Result<Output, Error> {
    if input.is_empty() {
        return Err(Error::EmptyInput);
    }
    
    let mut result = Vec::new();
    for option in options {
        if option.starts_with("prefix_") {
            if let Some(value) = option.strip_prefix("prefix_") {
                if config.enable_processing {
                    if value.len() > 10 {
                        if value.contains("special") {
                            result.push(process_special(value)?);
                        } else {
                            result.push(process_normal(value)?);
                        }
                    }
                }
            }
        }
    }
    
    Ok(Output { results: result })
}
"#;

    match server.predict_quality_issues(sample_code).await {
        Ok(prediction) => {
            info!("✅ Quality prediction successful!");
            info!("  Confidence: {:.2}%", prediction.confidence * 100.0);
            info!("  Issues found: {}", prediction.predictions.len());
            
            for (i, issue) in prediction.predictions.iter().take(3).enumerate() {
                info!("  Issue {}: {:?} at {}:{} - {}", 
                      i + 1, issue.issue_type, issue.location.file, 
                      issue.location.line, issue.description);
            }
        }
        Err(e) => error!("❌ Quality prediction failed: {}", e),
    }

    // Demo 3: Quality Score Analysis
    info!("\n3. Testing quality score analysis...");
    match server.get_quality_score(sample_code).await {
        Ok(score) => {
            info!("✅ Quality scoring successful!");
            info!("  Overall Score: {:.2}/1.0", score.overall_score);
            info!("  Maintainability: {:.2}/1.0", score.maintainability_score);
            info!("  Reliability: {:.2}/1.0", score.reliability_score);
            info!("  Security: {:.2}/1.0", score.security_score);
            info!("  Performance: {:.2}/1.0", score.performance_score);
            info!("  Testability: {:.2}/1.0", score.testability_score);
            info!("  Cyclomatic Complexity: {:.1}", score.detailed_metrics.cyclomatic_complexity);
            info!("  Code Duplication: {:.2}%", score.detailed_metrics.code_duplication * 100.0);
        }
        Err(e) => error!("❌ Quality scoring failed: {}", e),
    }

    // Demo 4: Performance Profiling
    info!("\n4. Testing performance profiling...");
    match server.profile_performance("sample_code_analysis").await {
        Ok(profile) => {
            info!("✅ Performance profiling successful!");
            info!("  Functions analyzed: {}", profile.profile.function_profiles.len());
            info!("  Memory peak usage: {:.2} MB", 
                  profile.profile.memory_profile.peak_usage as f64 / (1024.0 * 1024.0));
            info!("  CPU usage: {:.1}%", profile.profile.cpu_profile.usage_percentage);
            info!("  Bottlenecks detected: {}", profile.profile.bottlenecks.len());
            info!("  Optimization suggestions: {}", profile.suggestions.len());
        }
        Err(e) => error!("❌ Performance profiling failed: {}", e),
    }

    info!("\n✅ All Quality MCP Server features demonstrated successfully!");
    
    Ok(())
}
"