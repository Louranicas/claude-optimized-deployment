//! Task scheduler for orchestration engine
//! 
//! Provides intelligent scheduling of deployment tasks with priority-based
//! execution and resource-aware placement.

use super::*;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn, instrument};

/// Scheduler configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerConfig {
    /// Maximum queue size
    pub max_queue_size: usize,
    /// Scheduling interval in milliseconds
    pub scheduling_interval_ms: u64,
    /// Enable preemption
    pub preemption_enabled: bool,
    /// Resource overcommit ratio
    pub overcommit_ratio: f64,
    /// Priority boost for waiting tasks
    pub priority_boost_per_second: u32,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            max_queue_size: 10000,
            scheduling_interval_ms: 100,
            preemption_enabled: true,
            overcommit_ratio: 1.2,
            priority_boost_per_second: 1,
        }
    }
}

/// Deployment task for scheduling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentTask {
    pub service_id: Uuid,
    pub service_name: String,
    pub version: String,
    pub resources: ResourceRequest,
    pub priority: u32,
}

/// Internal task wrapper with scheduling metadata
#[derive(Debug, Clone)]
struct ScheduledTask {
    task: DeploymentTask,
    submitted_at: chrono::DateTime<chrono::Utc>,
    scheduled_at: Option<chrono::DateTime<chrono::Utc>>,
    effective_priority: u32,
}

impl ScheduledTask {
    fn new(task: DeploymentTask) -> Self {
        Self {
            effective_priority: task.priority,
            task,
            submitted_at: chrono::Utc::now(),
            scheduled_at: None,
        }
    }
    
    /// Update effective priority based on wait time
    fn update_priority(&mut self, boost_per_second: u32) {
        let wait_time = chrono::Utc::now() - self.submitted_at;
        let seconds_waited = wait_time.num_seconds() as u32;
        self.effective_priority = self.task.priority + (seconds_waited * boost_per_second);
    }
}

impl Eq for ScheduledTask {}

impl PartialEq for ScheduledTask {
    fn eq(&self, other: &Self) -> bool {
        self.task.service_id == other.task.service_id
    }
}

impl Ord for ScheduledTask {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first
        other.effective_priority.cmp(&self.effective_priority)
            .then_with(|| self.submitted_at.cmp(&other.submitted_at))
    }
}

impl PartialOrd for ScheduledTask {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Task scheduler
pub struct Scheduler {
    config: SchedulerConfig,
    task_queue: Arc<Mutex<BinaryHeap<ScheduledTask>>>,
    running_tasks: Arc<RwLock<HashMap<Uuid, ScheduledTask>>>,
    task_history: Arc<RwLock<Vec<TaskHistoryEntry>>>,
    resource_tracker: Arc<RwLock<ResourceTracker>>,
}

/// Task execution history entry
#[derive(Debug, Clone)]
struct TaskHistoryEntry {
    service_id: Uuid,
    service_name: String,
    submitted_at: chrono::DateTime<chrono::Utc>,
    started_at: chrono::DateTime<chrono::Utc>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
    wait_time_ms: u64,
    execution_time_ms: Option<u64>,
    success: Option<bool>,
}

/// Resource tracking for scheduling decisions
#[derive(Debug, Default)]
struct ResourceTracker {
    total_cpu: f64,
    used_cpu: f64,
    total_memory_mb: u64,
    used_memory_mb: u64,
    total_disk_mb: u64,
    used_disk_mb: u64,
}

impl Scheduler {
    /// Create a new scheduler
    pub fn new(config: SchedulerConfig) -> Self {
        Self {
            config,
            task_queue: Arc::new(Mutex::new(BinaryHeap::new())),
            running_tasks: Arc::new(RwLock::new(HashMap::new())),
            task_history: Arc::new(RwLock::new(Vec::new())),
            resource_tracker: Arc::new(RwLock::new(ResourceTracker::default())),
        }
    }
    
    /// Schedule a deployment task
    #[instrument(skip(self))]
    pub async fn schedule_deployment(&self, task: DeploymentTask) -> OrchestratorResult<()> {
        let mut queue = self.task_queue.lock().await;
        
        if queue.len() >= self.config.max_queue_size {
            return Err(OrchestratorError::ResourceLimitExceeded(
                "Task queue is full".to_string()
            ));
        }
        
        let scheduled_task = ScheduledTask::new(task);
        queue.push(scheduled_task);
        
        debug!("Task scheduled, queue size: {}", queue.len());
        Ok(())
    }
    
    /// Get next task to execute based on priority and resources
    pub async fn get_next_task(&self) -> Option<DeploymentTask> {
        let mut queue = self.task_queue.lock().await;
        let resource_tracker = self.resource_tracker.read().await;
        
        // Update priorities based on wait time
        let boost_per_second = self.config.priority_boost_per_second;
        let mut temp_queue = Vec::new();
        
        while let Some(mut task) = queue.pop() {
            task.update_priority(boost_per_second);
            temp_queue.push(task);
        }
        
        // Rebuild heap with updated priorities
        for task in temp_queue {
            queue.push(task);
        }
        
        // Find next runnable task
        let mut candidates = Vec::new();
        while let Some(task) = queue.pop() {
            if self.can_schedule(&task.task, &resource_tracker) {
                // Mark as scheduled
                let mut scheduled_task = task.clone();
                scheduled_task.scheduled_at = Some(chrono::Utc::now());
                
                // Track running task
                let mut running = self.running_tasks.write().await;
                running.insert(task.task.service_id, scheduled_task.clone());
                
                // Update resource usage
                drop(resource_tracker);
                let mut tracker = self.resource_tracker.write().await;
                tracker.used_cpu += task.task.resources.cpu_cores;
                tracker.used_memory_mb += task.task.resources.memory_mb;
                tracker.used_disk_mb += task.task.resources.disk_mb;
                
                // Add to history
                let history_entry = TaskHistoryEntry {
                    service_id: task.task.service_id,
                    service_name: task.task.service_name.clone(),
                    submitted_at: task.submitted_at,
                    started_at: chrono::Utc::now(),
                    completed_at: None,
                    wait_time_ms: (chrono::Utc::now() - task.submitted_at).num_milliseconds() as u64,
                    execution_time_ms: None,
                    success: None,
                };
                
                let mut history = self.task_history.write().await;
                history.push(history_entry);
                
                // Restore other candidates to queue
                for candidate in candidates {
                    queue.push(candidate);
                }
                
                return Some(task.task);
            } else {
                candidates.push(task);
            }
        }
        
        // No runnable task found, restore all candidates
        for candidate in candidates {
            queue.push(candidate);
        }
        
        None
    }
    
    /// Check if task can be scheduled with current resources
    fn can_schedule(&self, task: &DeploymentTask, tracker: &ResourceTracker) -> bool {
        let overcommit = self.config.overcommit_ratio;
        
        let cpu_available = (tracker.total_cpu * overcommit) - tracker.used_cpu;
        let memory_available = ((tracker.total_memory_mb as f64) * overcommit) as u64 - tracker.used_memory_mb;
        let disk_available = ((tracker.total_disk_mb as f64) * overcommit) as u64 - tracker.used_disk_mb;
        
        task.resources.cpu_cores <= cpu_available &&
        task.resources.memory_mb <= memory_available &&
        task.resources.disk_mb <= disk_available
    }
    
    /// Mark task as completed
    pub async fn complete_task(&self, service_id: Uuid, success: bool) -> OrchestratorResult<()> {
        // Remove from running tasks
        let task = {
            let mut running = self.running_tasks.write().await;
            running.remove(&service_id)
        };
        
        if let Some(task) = task {
            // Release resources
            let mut tracker = self.resource_tracker.write().await;
            tracker.used_cpu -= task.task.resources.cpu_cores;
            tracker.used_memory_mb -= task.task.resources.memory_mb;
            tracker.used_disk_mb -= task.task.resources.disk_mb;
            
            // Update history
            let mut history = self.task_history.write().await;
            if let Some(entry) = history.iter_mut().rev().find(|e| e.service_id == service_id) {
                entry.completed_at = Some(chrono::Utc::now());
                entry.execution_time_ms = Some(
                    (chrono::Utc::now() - entry.started_at).num_milliseconds() as u64
                );
                entry.success = Some(success);
            }
        }
        
        Ok(())
    }
    
    /// Cancel a scheduled task
    pub async fn cancel_task(&self, service_id: Uuid) -> OrchestratorResult<()> {
        let mut queue = self.task_queue.lock().await;
        
        // Remove from queue if present
        let mut temp_queue = Vec::new();
        while let Some(task) = queue.pop() {
            if task.task.service_id != service_id {
                temp_queue.push(task);
            }
        }
        
        for task in temp_queue {
            queue.push(task);
        }
        
        // Remove from running tasks
        self.complete_task(service_id, false).await?;
        
        Ok(())
    }
    
    /// Get scheduler statistics
    pub async fn get_stats(&self) -> SchedulerStats {
        let queue = self.task_queue.lock().await;
        let running = self.running_tasks.read().await;
        let history = self.task_history.read().await;
        let tracker = self.resource_tracker.read().await;
        
        let completed_tasks = history.iter().filter(|e| e.completed_at.is_some()).count();
        let successful_tasks = history.iter().filter(|e| e.success == Some(true)).count();
        let failed_tasks = history.iter().filter(|e| e.success == Some(false)).count();
        
        let avg_wait_time = if !history.is_empty() {
            history.iter().map(|e| e.wait_time_ms).sum::<u64>() / history.len() as u64
        } else {
            0
        };
        
        let avg_execution_time = {
            let completed: Vec<_> = history.iter()
                .filter_map(|e| e.execution_time_ms)
                .collect();
            if !completed.is_empty() {
                completed.iter().sum::<u64>() / completed.len() as u64
            } else {
                0
            }
        };
        
        SchedulerStats {
            queued_tasks: queue.len(),
            running_tasks: running.len(),
            completed_tasks,
            successful_tasks,
            failed_tasks,
            average_wait_time_ms: avg_wait_time,
            average_execution_time_ms: avg_execution_time,
            cpu_utilization: if tracker.total_cpu > 0.0 {
                tracker.used_cpu / tracker.total_cpu
            } else {
                0.0
            },
            memory_utilization: if tracker.total_memory_mb > 0 {
                tracker.used_memory_mb as f64 / tracker.total_memory_mb as f64
            } else {
                0.0
            },
        }
    }
    
    /// Update resource capacity
    pub async fn update_capacity(&self, cpu: f64, memory_mb: u64, disk_mb: u64) {
        let mut tracker = self.resource_tracker.write().await;
        tracker.total_cpu = cpu;
        tracker.total_memory_mb = memory_mb;
        tracker.total_disk_mb = disk_mb;
    }
}

/// Scheduler statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerStats {
    pub queued_tasks: usize,
    pub running_tasks: usize,
    pub completed_tasks: usize,
    pub successful_tasks: usize,
    pub failed_tasks: usize,
    pub average_wait_time_ms: u64,
    pub average_execution_time_ms: u64,
    pub cpu_utilization: f64,
    pub memory_utilization: f64,
}

/// Resource request for deployments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequest {
    pub cpu_cores: f64,
    pub memory_mb: u64,
    pub disk_mb: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_scheduler_creation() {
        let config = SchedulerConfig::default();
        let scheduler = Scheduler::new(config);
        
        let stats = scheduler.get_stats().await;
        assert_eq!(stats.queued_tasks, 0);
        assert_eq!(stats.running_tasks, 0);
    }
    
    #[tokio::test]
    async fn test_task_scheduling() {
        let config = SchedulerConfig::default();
        let scheduler = Scheduler::new(config);
        
        // Set capacity
        scheduler.update_capacity(4.0, 8192, 10240).await;
        
        let task = DeploymentTask {
            service_id: Uuid::new_v4(),
            service_name: "test-service".to_string(),
            version: "1.0.0".to_string(),
            resources: ResourceRequest {
                cpu_cores: 1.0,
                memory_mb: 1024,
                disk_mb: 2048,
            },
            priority: 100,
        };
        
        scheduler.schedule_deployment(task.clone()).await.unwrap();
        
        let stats = scheduler.get_stats().await;
        assert_eq!(stats.queued_tasks, 1);
        
        let next_task = scheduler.get_next_task().await;
        assert!(next_task.is_some());
        assert_eq!(next_task.unwrap().service_id, task.service_id);
    }
    
    #[tokio::test]
    async fn test_priority_scheduling() {
        let config = SchedulerConfig::default();
        let scheduler = Scheduler::new(config);
        
        scheduler.update_capacity(4.0, 8192, 10240).await;
        
        // Schedule low priority task
        let low_priority = DeploymentTask {
            service_id: Uuid::new_v4(),
            service_name: "low-priority".to_string(),
            version: "1.0.0".to_string(),
            resources: ResourceRequest {
                cpu_cores: 1.0,
                memory_mb: 1024,
                disk_mb: 1024,
            },
            priority: 50,
        };
        
        // Schedule high priority task
        let high_priority = DeploymentTask {
            service_id: Uuid::new_v4(),
            service_name: "high-priority".to_string(),
            version: "1.0.0".to_string(),
            resources: ResourceRequest {
                cpu_cores: 1.0,
                memory_mb: 1024,
                disk_mb: 1024,
            },
            priority: 150,
        };
        
        scheduler.schedule_deployment(low_priority.clone()).await.unwrap();
        scheduler.schedule_deployment(high_priority.clone()).await.unwrap();
        
        // High priority should be scheduled first
        let next = scheduler.get_next_task().await.unwrap();
        assert_eq!(next.service_id, high_priority.service_id);
    }
}