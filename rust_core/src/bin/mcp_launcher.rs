//! MCP Server Launcher Binary
//!
//! Production-grade launcher for all MCP servers with bulletproof reliability

use claude_optimized_deployment_rust::mcp_manager::launcher::launch_mcp_servers;
use std::process;

#[tokio::main]
async fn main() {
    println!("🦀 Rust MCP Server Launcher v1.0.0");
    println!("================================");

    match launch_mcp_servers().await {
        Ok(_) => {
            println!("✅ MCP servers shutdown gracefully");
            process::exit(0);
        }
        Err(e) => {
            eprintln!("❌ Fatal error: {}", e);
            process::exit(1);
        }
    }
}
