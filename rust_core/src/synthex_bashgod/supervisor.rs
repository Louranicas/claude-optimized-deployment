//! Supervisor Implementation for BashGod Actors
//! 
//! Implements supervision strategies for fault tolerance and error recovery
//! using the actor model's supervision tree pattern.

use super::{
    actor::{BashGodActor, ActorConfig},
    messages::BashGodMessage,
    BashGodError, Result,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

/// Supervision strategy for actor failures
#[derive(Debug, Clone)]
pub enum SupervisionStrategy {
    /// Restart only the failed actor
    OneForOne,
    /// Restart all actors if one fails
    OneForAll,
    /// Restart the failed actor and all actors started after it
    RestForOne,
    /// Custom strategy with backoff
    Exponential {
        initial_delay_ms: u64,
        max_delay_ms: u64,
        max_retries: u32,
    },
}

/// Actor supervision state
#[derive(Debug)]
struct ActorState {
    id: String,
    handle: Option<JoinHandle<()>>,
    sender: mpsc::Sender<BashGodMessage>,
    restart_count: u32,
    last_restart: Option<Instant>,
    config: ActorConfig,
}

/// BashGod supervisor that manages actor lifecycle
pub struct BashGodSupervisor {
    /// Supervised actors
    actors: Arc<RwLock<HashMap<String, ActorState>>>,
    /// Supervision strategy
    strategy: SupervisionStrategy,
    /// Runtime reference
    runtime: Arc<super::BashGodRuntime>,
    /// Supervisor control channel
    control_rx: Arc<RwLock<mpsc::Receiver<SupervisorCommand>>>,
    control_tx: mpsc::Sender<SupervisorCommand>,
}

/// Commands for supervisor control
#[derive(Debug)]
enum SupervisorCommand {
    /// Start a new actor
    StartActor {
        id: String,
        config: ActorConfig,
    },
    /// Stop an actor
    StopActor {
        id: String,
    },
    /// Restart an actor
    RestartActor {
        id: String,
        reason: String,
    },
    /// Update supervision strategy
    UpdateStrategy {
        strategy: SupervisionStrategy,
    },
    /// Shutdown supervisor
    Shutdown,
}

impl BashGodSupervisor {
    /// Create a new supervisor
    pub fn new(
        runtime: Arc<super::BashGodRuntime>,
        strategy: SupervisionStrategy,
    ) -> Self {
        let (control_tx, control_rx) = mpsc::channel(100);
        
        Self {
            actors: Arc::new(RwLock::new(HashMap::new())),
            strategy,
            runtime,
            control_rx: Arc::new(RwLock::new(control_rx)),
            control_tx,
        }
    }
    
    /// Start the supervisor
    pub async fn start(&self) -> Result<()> {
        info!("Starting BashGod supervisor");
        
        // Start the supervision loop
        let actors = self.actors.clone();
        let strategy = self.strategy.clone();
        let control_rx = self.control_rx.clone();
        
        tokio::spawn(async move {
            Self::supervision_loop(actors, strategy, control_rx).await;
        });
        
        // Start initial actors
        self.start_initial_actors().await?;
        
        Ok(())
    }
    
    /// Stop the supervisor
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping BashGod supervisor");
        
        // Send shutdown command
        self.control_tx.send(SupervisorCommand::Shutdown).await
            .map_err(|_| BashGodError::Supervision("Failed to send shutdown".to_string()))?;
        
        // Stop all actors
        let actors = self.actors.read().await;
        for (id, _) in actors.iter() {
            self.stop_actor(id).await?;
        }
        
        Ok(())
    }
    
    /// Start initial set of actors
    async fn start_initial_actors(&self) -> Result<()> {
        // Start a default actor
        self.start_actor("default", ActorConfig::default()).await?;
        Ok(())
    }
    
    /// Start a new actor
    pub async fn start_actor(&self, id: &str, config: ActorConfig) -> Result<()> {
        self.control_tx.send(SupervisorCommand::StartActor {
            id: id.to_string(),
            config,
        }).await
            .map_err(|_| BashGodError::Supervision("Failed to send start command".to_string()))?;
        Ok(())
    }
    
    /// Stop an actor
    pub async fn stop_actor(&self, id: &str) -> Result<()> {
        self.control_tx.send(SupervisorCommand::StopActor {
            id: id.to_string(),
        }).await
            .map_err(|_| BashGodError::Supervision("Failed to send stop command".to_string()))?;
        Ok(())
    }
    
    /// Main supervision loop
    async fn supervision_loop(
        actors: Arc<RwLock<HashMap<String, ActorState>>>,
        mut strategy: SupervisionStrategy,
        control_rx: Arc<RwLock<mpsc::Receiver<SupervisorCommand>>>,
    ) {
        let mut control_rx = control_rx.write().await;
        
        loop {
            if let Some(command) = control_rx.recv().await {
                match command {
                    SupervisorCommand::StartActor { id, config } => {
                        Self::handle_start_actor(actors.clone(), id, config).await;
                    }
                    
                    SupervisorCommand::StopActor { id } => {
                        Self::handle_stop_actor(actors.clone(), &id).await;
                    }
                    
                    SupervisorCommand::RestartActor { id, reason } => {
                        Self::handle_restart_actor(
                            actors.clone(),
                            &id,
                            &reason,
                            &strategy
                        ).await;
                    }
                    
                    SupervisorCommand::UpdateStrategy { strategy: new_strategy } => {
                        strategy = new_strategy;
                        info!("Updated supervision strategy: {:?}", strategy);
                    }
                    
                    SupervisorCommand::Shutdown => {
                        info!("Supervisor shutting down");
                        break;
                    }
                }
            }
            
            // Check actor health
            Self::check_actor_health(actors.clone()).await;
            
            // Small delay to prevent busy loop
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    
    /// Handle actor start
    async fn handle_start_actor(
        actors: Arc<RwLock<HashMap<String, ActorState>>>,
        id: String,
        config: ActorConfig,
    ) {
        let (tx, rx) = mpsc::channel(1000);
        
        // Create and start actor
        let actor = BashGodActor::new(rx, config.clone(), None);
        let handle = tokio::spawn(async move {
            actor.run().await;
        });
        
        // Store actor state
        let state = ActorState {
            id: id.clone(),
            handle: Some(handle),
            sender: tx,
            restart_count: 0,
            last_restart: None,
            config,
        };
        
        actors.write().await.insert(id.clone(), state);
        info!("Started actor: {}", id);
    }
    
    /// Handle actor stop
    async fn handle_stop_actor(
        actors: Arc<RwLock<HashMap<String, ActorState>>>,
        id: &str,
    ) {
        if let Some(mut state) = actors.write().await.remove(id) {
            // Send shutdown message
            let (response, rx) = tokio::sync::oneshot::channel();
            let _ = state.sender.send(BashGodMessage::Command(
                super::messages::BashGodCommand::Shutdown { response }
            )).await;
            
            // Wait for shutdown
            let _ = rx.await;
            
            // Abort handle if still running
            if let Some(handle) = state.handle.take() {
                handle.abort();
            }
            
            info!("Stopped actor: {}", id);
        }
    }
    
    /// Handle actor restart with strategy
    async fn handle_restart_actor(
        actors: Arc<RwLock<HashMap<String, ActorState>>>,
        id: &str,
        reason: &str,
        strategy: &SupervisionStrategy,
    ) {
        warn!("Restarting actor {} due to: {}", id, reason);
        
        match strategy {
            SupervisionStrategy::OneForOne => {
                // Restart only this actor
                if let Some(state) = actors.read().await.get(id) {
                    let config = state.config.clone();
                    Self::handle_stop_actor(actors.clone(), id).await;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Self::handle_start_actor(actors.clone(), id.to_string(), config).await;
                }
            }
            
            SupervisionStrategy::OneForAll => {
                // Restart all actors
                let actor_ids: Vec<String> = actors.read().await.keys().cloned().collect();
                let configs: Vec<(String, ActorConfig)> = {
                    let actors_read = actors.read().await;
                    actor_ids.iter()
                        .filter_map(|id| {
                            actors_read.get(id).map(|s| (id.clone(), s.config.clone()))
                        })
                        .collect()
                };
                
                // Stop all
                for actor_id in &actor_ids {
                    Self::handle_stop_actor(actors.clone(), actor_id).await;
                }
                
                // Restart all
                for (actor_id, config) in configs {
                    Self::handle_start_actor(actors.clone(), actor_id, config).await;
                }
            }
            
            SupervisionStrategy::RestForOne => {
                // Find position of failed actor and restart it plus all after
                let actor_ids: Vec<String> = actors.read().await.keys().cloned().collect();
                if let Some(pos) = actor_ids.iter().position(|x| x == id) {
                    let to_restart = &actor_ids[pos..];
                    
                    for actor_id in to_restart {
                        if let Some(state) = actors.read().await.get(actor_id) {
                            let config = state.config.clone();
                            Self::handle_stop_actor(actors.clone(), actor_id).await;
                            Self::handle_start_actor(actors.clone(), actor_id.clone(), config).await;
                        }
                    }
                }
            }
            
            SupervisionStrategy::Exponential { initial_delay_ms, max_delay_ms, max_retries } => {
                // Calculate backoff delay
                let mut actors_write = actors.write().await;
                if let Some(state) = actors_write.get_mut(id) {
                    if state.restart_count >= *max_retries {
                        error!("Actor {} exceeded max retries ({}), not restarting", id, max_retries);
                        return;
                    }
                    
                    let delay = (*initial_delay_ms * 2u64.pow(state.restart_count))
                        .min(*max_delay_ms);
                    
                    state.restart_count += 1;
                    state.last_restart = Some(Instant::now());
                    
                    let config = state.config.clone();
                    drop(actors_write);
                    
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    Self::handle_stop_actor(actors.clone(), id).await;
                    Self::handle_start_actor(actors.clone(), id.to_string(), config).await;
                }
            }
        }
    }
    
    /// Check health of all actors
    async fn check_actor_health(actors: Arc<RwLock<HashMap<String, ActorState>>>) {
        let actors_read = actors.read().await;
        
        for (id, state) in actors_read.iter() {
            if let Some(handle) = &state.handle {
                if handle.is_finished() {
                    warn!("Actor {} has stopped unexpectedly", id);
                    // TODO: Trigger restart
                }
            }
        }
    }
    
    /// Get actor statistics
    pub async fn get_stats(&self) -> SupervisorStats {
        let actors = self.actors.read().await;
        
        SupervisorStats {
            total_actors: actors.len(),
            active_actors: actors.values().filter(|s| s.handle.is_some()).count(),
            total_restarts: actors.values().map(|s| s.restart_count).sum(),
            strategy: format!("{:?}", self.strategy),
        }
    }
}

/// Supervisor statistics
#[derive(Debug, Clone)]
pub struct SupervisorStats {
    pub total_actors: usize,
    pub active_actors: usize,
    pub total_restarts: u32,
    pub strategy: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_supervisor_lifecycle() {
        let runtime = Arc::new(super::super::BashGodRuntime::new(
            super::super::RuntimeConfig::default()
        ));
        
        let supervisor = BashGodSupervisor::new(
            runtime,
            SupervisionStrategy::OneForOne,
        );
        
        // Start supervisor
        assert!(supervisor.start().await.is_ok());
        
        // Get initial stats
        let stats = supervisor.get_stats().await;
        assert_eq!(stats.total_actors, 1); // Default actor
        
        // Start another actor
        supervisor.start_actor("test-actor", ActorConfig::default()).await.unwrap();
        
        // Check stats
        let stats = supervisor.get_stats().await;
        assert_eq!(stats.total_actors, 2);
        
        // Stop supervisor
        assert!(supervisor.stop().await.is_ok());
    }
}