/*!
 * Rust MCP Server Template
 * 
 * This template provides a complete example of how to implement
 * an MCP server using standardized Rust patterns and best practices.
 */

use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, error};

mod server;
mod config;
mod tools;
mod resources;
mod health;
mod errors;

use server::TemplateServer;
use config::ServerConfig;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "config.toml")]
    config: String,
    
    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,
    
    /// Disable health checks
    #[arg(long)]
    no_health_checks: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(&args.log_level)
        .with_target(false)
        .init();
    
    info!("Starting Template MCP Server");
    
    // Load configuration
    let config = ServerConfig::load(&args.config).await?;
    
    // Create server instance
    let server = Arc::new(TemplateServer::new(config).await?);
    
    // Setup graceful shutdown
    let server_clone = Arc::clone(&server);
    tokio::spawn(async move {
        match signal::ctrl_c().await {
            Ok(()) => {
                info!("Received SIGINT, shutting down gracefully");
                if let Err(e) = server_clone.shutdown().await {
                    error!("Error during shutdown: {}", e);
                }
                std::process::exit(0);
            }
            Err(e) => {
                error!("Failed to listen for shutdown signal: {}", e);
            }
        }
    });
    
    // Start the server
    server.start().await?;
    
    Ok(())
}