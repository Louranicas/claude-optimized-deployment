use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, warn, error, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::sync::Arc;

mod orchestrator;
mod services;
mod resources;
mod network;
mod reliability;
mod monitoring;
mod config;

use orchestrator::DeploymentOrchestrator;

#[derive(Parser)]
#[command(
    name = "deploy-code",
    version = "1.0.0",
    about = "Bulletproof deployment orchestrator for CODE environment",
    long_about = "Deploy and manage all CODE platform services with a single command"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    
    /// Configuration file path
    #[arg(short, long, default_value = "deploy-code.yaml")]
    config: String,
    
    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,
    
    /// Dry run mode - simulate deployment without executing
    #[arg(long)]
    dry_run: bool,
    
    /// Force deployment even if health checks fail
    #[arg(long)]
    force: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Deploy all CODE services
    Deploy {
        /// Deploy only specific services (comma-separated)
        #[arg(short, long)]
        services: Option<String>,
        
        /// Skip specific deployment phases
        #[arg(long)]
        skip_phases: Option<String>,
    },
    
    /// Stop all CODE services
    Stop {
        /// Graceful shutdown timeout in seconds
        #[arg(short, long, default_value = "30")]
        timeout: u64,
    },
    
    /// Check status of all services
    Status {
        /// Show detailed status information
        #[arg(short, long)]
        detailed: bool,
    },
    
    /// Restart services
    Restart {
        /// Services to restart (comma-separated)
        #[arg(short, long)]
        services: Option<String>,
    },
    
    /// Validate deployment configuration
    Validate,
    
    /// Show deployment health
    Health {
        /// Output format (json, yaml, text)
        #[arg(short, long, default_value = "text")]
        format: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    init_logging(&cli.log_level)?;
    
    info!("CODE Deployment Orchestrator v1.0.0");
    info!("Starting deployment engine...");
    
    // Load configuration
    let config = config::load_config(std::path::Path::new(&cli.config)).await?;
    
    // Initialize orchestrator
    let orchestrator = Arc::new(
        DeploymentOrchestrator::new(config, cli.dry_run, cli.force).await?
    );
    
    // Execute command
    match cli.command {
        Some(Commands::Deploy { services, skip_phases }) => {
            deploy_services(orchestrator, services, skip_phases).await?;
        }
        Some(Commands::Stop { timeout }) => {
            stop_services(orchestrator, timeout).await?;
        }
        Some(Commands::Status { detailed }) => {
            show_status(orchestrator, detailed).await?;
        }
        Some(Commands::Restart { services }) => {
            restart_services(orchestrator, services).await?;
        }
        Some(Commands::Validate) => {
            validate_configuration(orchestrator).await?;
        }
        Some(Commands::Health { format }) => {
            show_health(orchestrator, &format).await?;
        }
        None => {
            // Default action: deploy all services
            deploy_services(orchestrator, None, None).await?;
        }
    }
    
    Ok(())
}

fn init_logging(level: &str) -> Result<()> {
    let level = match level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };
    
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("deploy_code={},tower_http=info", level).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    
    Ok(())
}

async fn deploy_services(
    orchestrator: Arc<DeploymentOrchestrator>,
    services: Option<String>,
    skip_phases: Option<String>,
) -> Result<()> {
    info!("Starting CODE platform deployment...");
    
    let service_list = services
        .map(|s| s.split(',').map(String::from).collect::<Vec<_>>())
        .unwrap_or_default();
    
    let skip_list = skip_phases
        .map(|s| s.split(',').map(String::from).collect::<Vec<_>>())
        .unwrap_or_default();
    
    match orchestrator.deploy(service_list, skip_list).await {
        Ok(report) => {
            info!("Deployment completed successfully!");
            info!("Total services deployed: {}", report.total_services);
            info!("Deployment time: {:.2}s", report.duration.as_secs_f64());
            
            if report.warnings > 0 {
                warn!("Deployment completed with {} warnings", report.warnings);
            }
            
            Ok(())
        }
        Err(e) => {
            error!("Deployment failed: {}", e);
            
            // Attempt rollback
            warn!("Attempting automatic rollback...");
            if let Err(rollback_err) = orchestrator.rollback().await {
                error!("Rollback failed: {}", rollback_err);
            } else {
                info!("Rollback completed successfully");
            }
            
            Err(e)
        }
    }
}

async fn stop_services(
    orchestrator: Arc<DeploymentOrchestrator>,
    timeout: u64,
) -> Result<()> {
    info!("Stopping all CODE services...");
    
    orchestrator.stop_all(std::time::Duration::from_secs(timeout)).await?;
    
    info!("All services stopped successfully");
    Ok(())
}

async fn show_status(
    orchestrator: Arc<DeploymentOrchestrator>,
    detailed: bool,
) -> Result<()> {
    let status = orchestrator.get_status(detailed).await?;
    
    println!("\n=== CODE Platform Status ===\n");
    println!("Overall Health: {}", status.overall_health);
    println!("Total Services: {}", status.total_services);
    println!("Running Services: {}", status.running_services);
    println!("Failed Services: {}", status.failed_services);
    
    if detailed {
        println!("\n=== Service Details ===\n");
        for (service, details) in &status.services {
            println!("{}: {} ({})", 
                service, 
                details.status,
                details.health
            );
            if let Some(msg) = &details.message {
                println!("  Message: {}", msg);
            }
        }
    }
    
    Ok(())
}

async fn restart_services(
    orchestrator: Arc<DeploymentOrchestrator>,
    services: Option<String>,
) -> Result<()> {
    info!("Restarting services...");
    
    let service_list = services
        .map(|s| s.split(',').map(String::from).collect::<Vec<_>>())
        .unwrap_or_default();
    
    orchestrator.restart(service_list).await?;
    
    info!("Services restarted successfully");
    Ok(())
}

async fn validate_configuration(
    orchestrator: Arc<DeploymentOrchestrator>,
) -> Result<()> {
    info!("Validating deployment configuration...");
    
    match orchestrator.validate().await {
        Ok(validation) => {
            if validation.is_valid {
                info!("Configuration is valid!");
            } else {
                error!("Configuration validation failed!");
                for error in &validation.errors {
                    error!("  - {}", error);
                }
                return Err(anyhow::anyhow!("Invalid configuration"));
            }
            
            if !validation.warnings.is_empty() {
                warn!("Configuration warnings:");
                for warning in &validation.warnings {
                    warn!("  - {}", warning);
                }
            }
            
            Ok(())
        }
        Err(e) => {
            error!("Validation failed: {}", e);
            Err(e)
        }
    }
}

async fn show_health(
    orchestrator: Arc<DeploymentOrchestrator>,
    format: &str,
) -> Result<()> {
    let health = orchestrator.get_health().await?;
    
    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&health)?);
        }
        "yaml" => {
            println!("{}", serde_yaml::to_string(&health)?);
        }
        _ => {
            println!("\n=== CODE Platform Health ===\n");
            println!("Status: {}", health.status);
            println!("Score: {}/100", health.score);
            println!("Uptime: {:.2} hours", health.uptime_hours);
            
            if !health.issues.is_empty() {
                println!("\n=== Active Issues ===\n");
                for issue in &health.issues {
                    println!("- [{}] {}", issue.severity, issue.message);
                }
            }
        }
    }
    
    Ok(())
}