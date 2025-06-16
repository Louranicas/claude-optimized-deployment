// ============================================================================
// MCP SERVER DEMO - Example usage of the MCP server implementations
// ============================================================================

use claude_optimized_deployment_rust::mcp_manager::{
    server::{ServerConfig, ServerType},
    server_types::{
        create_mcp_server, DockerConfig, PrometheusConfig, SASTConfig, ServerCategory, Severity,
    },
};
use serde_json::json;
use tokio;
use tracing::{info, Level};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    info!("Starting MCP Server Demo");

    // Create a Docker server
    let docker_config = ServerConfig {
        server_type: ServerType::Http,
        endpoint: "unix:///var/run/docker.sock".to_string(),
        timeout_ms: 5000,
        max_retries: 3,
        circuit_breaker_enabled: true,
    };

    let docker_specific = json!({
        "socket_path": "/var/run/docker.sock",
        "api_version": "1.41"
    });

    let docker_server = create_mcp_server(
        "docker-demo",
        docker_config,
        ServerCategory::Infrastructure,
        "docker",
        docker_specific,
    )
    .await?;

    info!("Docker server created");

    // Get available tools
    let docker_tools = docker_server.get_tools().await?;
    info!("Docker server has {} tools available", docker_tools.len());
    for tool in &docker_tools[..3] {
        // Show first 3 tools
        info!("  - {}: {}", tool.name, tool.description);
    }

    // Create a Prometheus server
    let prom_config = ServerConfig {
        server_type: ServerType::Http,
        endpoint: "http://localhost:9090".to_string(),
        timeout_ms: 5000,
        max_retries: 3,
        circuit_breaker_enabled: true,
    };

    let prom_specific = json!({
        "prometheus_url": "http://localhost:9090",
        "timeout_secs": 30,
        "retention_days": 15
    });

    let prom_server = create_mcp_server(
        "prometheus-demo",
        prom_config,
        ServerCategory::Monitoring,
        "prometheus",
        prom_specific,
    )
    .await?;

    info!("Prometheus server created");

    // Get available tools
    let prom_tools = prom_server.get_tools().await?;
    info!("Prometheus server has {} tools available", prom_tools.len());
    for tool in &prom_tools[..3] {
        // Show first 3 tools
        info!("  - {}: {}", tool.name, tool.description);
    }

    // Create a SAST security server
    let sast_config = ServerConfig {
        server_type: ServerType::Custom("sast".to_string()),
        endpoint: "local".to_string(),
        timeout_ms: 30000,
        max_retries: 1,
        circuit_breaker_enabled: true,
    };

    let sast_specific = json!({
        "scanner_engine": "semgrep",
        "excluded_paths": ["node_modules", "vendor"],
        "severity_threshold": "Low",
        "max_file_size_mb": 100,
        "languages": ["python", "javascript", "rust"]
    });

    let sast_server = create_mcp_server(
        "sast-demo",
        sast_config,
        ServerCategory::Security,
        "sast",
        sast_specific,
    )
    .await?;

    info!("SAST server created");

    // Get available tools
    let sast_tools = sast_server.get_tools().await?;
    info!("SAST server has {} tools available", sast_tools.len());
    for tool in &sast_tools {
        info!("  - {}: {}", tool.name, tool.description);
    }

    // Demonstrate calling a tool
    info!("\nDemonstrating SAST code scan:");
    let scan_params = json!({
        "code": "password = 'hardcoded_secret_123'",
        "language": "python"
    });

    let scan_result = sast_server
        .call_tool(
            "sast_scan_code_snippet",
            serde_json::to_vec(&scan_params)?.into(),
        )
        .await?;

    let result_json: serde_json::Value = serde_json::from_slice(&scan_result)?;
    info!(
        "Scan result: {}",
        serde_json::to_string_pretty(&result_json)?
    );

    // Perform health checks
    info!("\nPerforming health checks:");

    let docker_health = docker_server.health_check().await?;
    info!(
        "Docker server health: {}",
        if docker_health { "OK" } else { "UNHEALTHY" }
    );

    let prom_health = prom_server.health_check().await?;
    info!(
        "Prometheus server health: {}",
        if prom_health { "OK" } else { "UNHEALTHY" }
    );

    let sast_health = sast_server.health_check().await?;
    info!(
        "SAST server health: {}",
        if sast_health { "OK" } else { "UNHEALTHY" }
    );

    // Shutdown servers
    info!("\nShutting down servers...");
    docker_server.shutdown().await?;
    prom_server.shutdown().await?;
    sast_server.shutdown().await?;

    info!("Demo completed successfully!");

    Ok(())
}
