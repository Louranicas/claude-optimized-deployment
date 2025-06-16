// SPDX-License-Identifier: MIT
// Claude↔PALMA Bridge – Multi-Agent Deployment Scaffold
// Language: Rust 2021 Edition

mod bridge;
mod agents;
mod memory;
mod comms;
mod scheduler;

use bridge::BridgeController;
use agents::AgentRegistry;
use memory::SharedMemoryStack;
use scheduler::TaskOrchestrator;
use std::sync::Arc;
use tokio::main;

#[main]
async fn main() {
    println!("🔗 Claude↔PALMA Bridge Initializing...");

    let memory = Arc::new(SharedMemoryStack::new());
    let agent_registry = Arc::new(AgentRegistry::default());

    // Initialize bridge
    let mut bridge = BridgeController::new(memory.clone(), agent_registry.clone());
    bridge.initialize_network_layer("0.0.0.0:8686").await;

    // Launch task orchestrator
    let mut orchestrator = TaskOrchestrator::new(memory, agent_registry);
    orchestrator.bootstrap_loop().await;

    println!("🌉 Claude↔PALMA Bridge Operational");
}