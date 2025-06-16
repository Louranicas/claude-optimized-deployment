//! Failover management for MCP servers

use crate::mcp_manager::{
    errors::{McpError, Result},
    server::{McpServer, ServerState},
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};

/// Failover strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailoverStrategy {
    /// Active-passive failover
    ActivePassive,
    /// Active-active failover
    ActiveActive,
    /// Priority-based failover
    PriorityBased,
    /// Geographic failover
    Geographic,
}

/// Failover manager for handling server failures
pub struct FailoverManager {
    /// Failover strategy
    strategy: FailoverStrategy,
    /// Primary servers by group
    primaries: Arc<RwLock<HashMap<String, Vec<Arc<McpServer>>>>>,
    /// Backup servers by group
    backups: Arc<RwLock<HashMap<String, Vec<Arc<McpServer>>>>>,
    /// Active failovers
    active_failovers: Arc<Mutex<HashMap<String, FailoverState>>>,
    /// Failover history
    history: Arc<Mutex<Vec<FailoverEvent>>>,
}

/// Failover state
#[derive(Debug, Clone)]
struct FailoverState {
    /// Failed server ID
    failed_server: String,
    /// Backup server ID
    backup_server: String,
    /// Failover start time
    started_at: Instant,
    /// Is automatic failback enabled
    auto_failback: bool,
}

/// Failover event
#[derive(Debug, Clone)]
pub struct FailoverEvent {
    /// Event ID
    pub id: String,
    /// Event type
    pub event_type: FailoverEventType,
    /// Source server
    pub source: String,
    /// Target server
    pub target: Option<String>,
    /// Timestamp
    pub timestamp: Instant,
    /// Success status
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Failover event types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverEventType {
    /// Server failure detected
    FailureDetected,
    /// Failover initiated
    FailoverInitiated,
    /// Failover completed
    FailoverCompleted,
    /// Failback initiated
    FailbackInitiated,
    /// Failback completed
    FailbackCompleted,
}

impl FailoverManager {
    /// Create a new failover manager
    pub fn new(strategy: FailoverStrategy) -> Self {
        Self {
            strategy,
            primaries: Arc::new(RwLock::new(HashMap::new())),
            backups: Arc::new(RwLock::new(HashMap::new())),
            active_failovers: Arc::new(Mutex::new(HashMap::new())),
            history: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Register primary server
    pub async fn register_primary(&self, group: String, server: Arc<McpServer>) {
        let mut primaries = self.primaries.write().await;
        primaries.entry(group).or_insert_with(Vec::new).push(server);
    }

    /// Register backup server
    pub async fn register_backup(&self, group: String, server: Arc<McpServer>) {
        let mut backups = self.backups.write().await;
        backups.entry(group).or_insert_with(Vec::new).push(server);
    }

    /// Handle server failure
    pub async fn handle_failure(&self, failed_server_id: &str) -> Result<String> {
        // Find which group the failed server belongs to
        let group = self.find_server_group(failed_server_id).await
            .ok_or_else(|| McpError::ServerNotFound(failed_server_id.to_string()))?;
        
        // Record failure event
        self.record_event(FailoverEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: FailoverEventType::FailureDetected,
            source: failed_server_id.to_string(),
            target: None,
            timestamp: Instant::now(),
            success: true,
            error: None,
        }).await;
        
        // Select backup server based on strategy
        let backup_server = self.select_backup(&group).await?;
        
        // Initiate failover
        self.initiate_failover(failed_server_id, &backup_server.id().to_string()).await?;
        
        Ok(backup_server.id().to_string())
    }

    /// Initiate failover
    async fn initiate_failover(&self, failed_server_id: &str, backup_server_id: &str) -> Result<()> {
        // Record failover initiation
        self.record_event(FailoverEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: FailoverEventType::FailoverInitiated,
            source: failed_server_id.to_string(),
            target: Some(backup_server_id.to_string()),
            timestamp: Instant::now(),
            success: true,
            error: None,
        }).await;
        
        // Store active failover state
        let mut active = self.active_failovers.lock().await;
        active.insert(failed_server_id.to_string(), FailoverState {
            failed_server: failed_server_id.to_string(),
            backup_server: backup_server_id.to_string(),
            started_at: Instant::now(),
            auto_failback: true,
        });
        
        // In production, this would:
        // 1. Update DNS/load balancer
        // 2. Migrate connections
        // 3. Sync state if needed
        
        // Record completion
        self.record_event(FailoverEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: FailoverEventType::FailoverCompleted,
            source: failed_server_id.to_string(),
            target: Some(backup_server_id.to_string()),
            timestamp: Instant::now(),
            success: true,
            error: None,
        }).await;
        
        Ok(())
    }

    /// Perform failback when primary recovers
    pub async fn failback(&self, recovered_server_id: &str) -> Result<()> {
        let active = self.active_failovers.lock().await;
        
        if let Some(failover_state) = active.get(recovered_server_id) {
            if !failover_state.auto_failback {
                return Ok(()); // Manual failback required
            }
            
            let backup_id = failover_state.backup_server.clone();
            drop(active); // Release lock
            
            // Record failback initiation
            self.record_event(FailoverEvent {
                id: uuid::Uuid::new_v4().to_string(),
                event_type: FailoverEventType::FailbackInitiated,
                source: backup_id.clone(),
                target: Some(recovered_server_id.to_string()),
                timestamp: Instant::now(),
                success: true,
                error: None,
            }).await;
            
            // Perform failback
            // In production: migrate connections back, update routing
            
            // Remove from active failovers
            self.active_failovers.lock().await.remove(recovered_server_id);
            
            // Record completion
            self.record_event(FailoverEvent {
                id: uuid::Uuid::new_v4().to_string(),
                event_type: FailoverEventType::FailbackCompleted,
                source: backup_id,
                target: Some(recovered_server_id.to_string()),
                timestamp: Instant::now(),
                success: true,
                error: None,
            }).await;
        }
        
        Ok(())
    }

    /// Select backup server based on strategy
    async fn select_backup(&self, group: &str) -> Result<Arc<McpServer>> {
        let backups = self.backups.read().await;
        let backup_list = backups.get(group)
            .ok_or_else(|| McpError::Other(format!("No backups for group: {}", group)))?;
        
        // Filter healthy backups
        let healthy_backups: Vec<&Arc<McpServer>> = stream::iter(backup_list.iter())
            .filter(|server| async move {
                server.state().await == ServerState::Healthy
            })
            .collect()
            .await;
        
        if healthy_backups.is_empty() {
            return Err(McpError::Other("No healthy backup servers available".to_string()));
        }
        
        // Select based on strategy
        let selected = match self.strategy {
            FailoverStrategy::ActivePassive => {
                // First healthy backup
                healthy_backups[0]
            }
            FailoverStrategy::ActiveActive => {
                // Random selection for load distribution
                use rand::seq::SliceRandom;
                healthy_backups.choose(&mut rand::thread_rng()).unwrap()
            }
            FailoverStrategy::PriorityBased => {
                // Highest priority backup
                healthy_backups.iter()
                    .max_by_key(|s| s.priority())
                    .unwrap()
            }
            FailoverStrategy::Geographic => {
                // In production: select based on geographic proximity
                // For now, just use first
                healthy_backups[0]
            }
        };
        
        Ok(selected.clone())
    }

    /// Find which group a server belongs to
    async fn find_server_group(&self, server_id: &str) -> Option<String> {
        let primaries = self.primaries.read().await;
        
        for (group, servers) in primaries.iter() {
            if servers.iter().any(|s| s.id() == server_id) {
                return Some(group.clone());
            }
        }
        
        let backups = self.backups.read().await;
        
        for (group, servers) in backups.iter() {
            if servers.iter().any(|s| s.id() == server_id) {
                return Some(group.clone());
            }
        }
        
        None
    }

    /// Record failover event
    async fn record_event(&self, event: FailoverEvent) {
        let mut history = self.history.lock().await;
        history.push(event);
        
        // Keep only last 1000 events
        if history.len() > 1000 {
            history.drain(0..history.len() - 1000);
        }
    }

    /// Get failover history
    pub async fn get_history(&self, limit: Option<usize>) -> Vec<FailoverEvent> {
        let history = self.history.lock().await;
        let limit = limit.unwrap_or(100);
        
        history.iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get active failovers
    pub async fn active_failovers(&self) -> HashMap<String, (String, Duration)> {
        let active = self.active_failovers.lock().await;
        
        active.iter()
            .map(|(k, v)| {
                (k.clone(), (v.backup_server.clone(), v.started_at.elapsed()))
            })
            .collect()
    }

    /// Check if server is in failover
    pub async fn is_failed_over(&self, server_id: &str) -> bool {
        self.active_failovers.lock().await.contains_key(server_id)
    }
}

use futures::stream::{self, StreamExt};

/// Failover group configuration
#[derive(Debug, Clone)]
pub struct FailoverGroup {
    /// Group name
    pub name: String,
    /// Primary servers
    pub primaries: Vec<String>,
    /// Backup servers
    pub backups: Vec<String>,
    /// Failover priority
    pub priority: u8,
    /// Geographic region
    pub region: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_manager::config::{ServerConfig, ServerType, AuthConfig};
    use std::time::Duration;

    fn create_test_server(id: &str, priority: u8) -> Arc<McpServer> {
        let config = ServerConfig {
            name: format!("test-{}", id),
            server_type: ServerType::Infrastructure,
            url: "http://localhost:8080".to_string(),
            auth: Some(AuthConfig::ApiKey {
                key: "test-key".to_string(),
            }),
            timeout: Some(Duration::from_secs(30)),
            max_retries: 3,
            priority,
            tags: vec![],
        };
        
        Arc::new(McpServer::new(id.to_string(), config).unwrap())
    }

    #[tokio::test]
    async fn test_failover_manager() {
        let manager = FailoverManager::new(FailoverStrategy::ActivePassive);
        
        // Register servers
        let primary = create_test_server("primary-1", 10);
        let backup = create_test_server("backup-1", 5);
        
        manager.register_primary("group-1".to_string(), primary).await;
        manager.register_backup("group-1".to_string(), backup).await;
        
        // Test failover
        let backup_id = manager.handle_failure("primary-1").await.unwrap();
        assert_eq!(backup_id, "backup-1");
        
        // Check active failovers
        assert!(manager.is_failed_over("primary-1").await);
    }

    #[tokio::test]
    async fn test_priority_failover() {
        let manager = FailoverManager::new(FailoverStrategy::PriorityBased);
        
        // Register backups with different priorities
        manager.register_backup("group-1".to_string(), create_test_server("backup-1", 5)).await;
        manager.register_backup("group-1".to_string(), create_test_server("backup-2", 10)).await;
        manager.register_backup("group-1".to_string(), create_test_server("backup-3", 7)).await;
        
        manager.register_primary("group-1".to_string(), create_test_server("primary-1", 15)).await;
        
        // Should select backup-2 (highest priority)
        let backup_id = manager.handle_failure("primary-1").await.unwrap();
        assert_eq!(backup_id, "backup-2");
    }

    #[tokio::test]
    async fn test_failover_history() {
        let manager = FailoverManager::new(FailoverStrategy::ActivePassive);
        
        let primary = create_test_server("primary-1", 10);
        let backup = create_test_server("backup-1", 5);
        
        manager.register_primary("group-1".to_string(), primary).await;
        manager.register_backup("group-1".to_string(), backup).await;
        
        // Perform failover
        manager.handle_failure("primary-1").await.unwrap();
        
        // Check history
        let history = manager.get_history(None).await;
        assert!(history.len() >= 3); // FailureDetected, FailoverInitiated, FailoverCompleted
        
        let failure_event = history.iter()
            .find(|e| e.event_type == FailoverEventType::FailureDetected)
            .unwrap();
        assert_eq!(failure_event.source, "primary-1");
    }
}