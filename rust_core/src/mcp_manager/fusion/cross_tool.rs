//! Cross-Tool Orchestrator - Orchestrate commands across multiple MCP tools
//! 
//! This module provides advanced orchestration capabilities for executing
//! complex workflows that span multiple MCP tools with transaction semantics.

use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex, Semaphore};
use tokio::time::timeout;
use futures::future::{join_all, select_all};
use tracing::{info, warn, error, debug, instrument};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

use crate::mcp_manager::{McpManager, Result, McpError};
use super::registry::ToolRegistry;

/// Cross-tool orchestrator for complex workflows
pub struct CrossToolOrchestrator {
    mcp_manager: Arc<McpManager>,
    tool_registry: Arc<RwLock<ToolRegistry>>,
    active_workflows: Arc<RwLock<HashMap<String, WorkflowState>>>,
    transaction_manager: Arc<TransactionManager>,
    semaphore: Arc<Semaphore>,
}

/// Workflow definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub steps: Vec<WorkflowStep>,
    pub transaction_mode: TransactionMode,
    pub timeout: Duration,
    pub retry_policy: RetryPolicy,
}

/// Individual workflow step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub id: String,
    pub tool: String,
    pub method: String,
    pub parameters: serde_json::Value,
    pub dependencies: Vec<String>,
    pub condition: Option<StepCondition>,
    pub transform: Option<DataTransform>,
    pub error_handler: ErrorHandler,
}

/// Condition for executing a step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepCondition {
    pub expression: String,
    pub variables: HashMap<String, String>,
}

/// Data transformation between steps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataTransform {
    /// JSONPath extraction
    JsonPath(String),
    /// JQ-style transformation
    Jq(String),
    /// Custom function
    Custom(String),
    /// Direct mapping
    Map(HashMap<String, String>),
}

/// Error handling strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorHandler {
    /// Fail the entire workflow
    Fail,
    /// Retry with backoff
    Retry { max_attempts: u32, backoff_ms: u64 },
    /// Skip and continue
    Skip,
    /// Use fallback value
    Fallback(serde_json::Value),
    /// Compensate with another action
    Compensate { tool: String, method: String, params: serde_json::Value },
}

/// Transaction mode for workflows
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionMode {
    /// No transaction support
    None,
    /// Best effort - try to rollback on failure
    BestEffort,
    /// Strict - all or nothing with guaranteed rollback
    Strict,
    /// Saga pattern - compensating transactions
    Saga,
}

/// Retry policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub exponential_base: f32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 100,
            max_delay_ms: 5000,
            exponential_base: 2.0,
        }
    }
}

/// Workflow execution state
#[derive(Debug)]
struct WorkflowState {
    workflow: Workflow,
    status: WorkflowStatus,
    current_step: Option<String>,
    step_results: HashMap<String, StepResult>,
    start_time: Instant,
    end_time: Option<Instant>,
    transaction_id: Option<String>,
}

/// Workflow status
#[derive(Debug, Clone, PartialEq)]
enum WorkflowStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    RollingBack,
}

/// Result of a workflow step
#[derive(Debug, Clone)]
struct StepResult {
    step_id: String,
    status: StepStatus,
    output: Option<serde_json::Value>,
    error: Option<String>,
    duration_ms: u64,
    attempts: u32,
}

/// Step execution status
#[derive(Debug, Clone, PartialEq)]
enum StepStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
    Compensated,
}

/// Transaction manager for handling rollbacks
struct TransactionManager {
    transactions: Arc<RwLock<HashMap<String, Transaction>>>,
}

/// Transaction information
#[derive(Debug)]
struct Transaction {
    id: String,
    steps: Vec<TransactionStep>,
    status: TransactionStatus,
}

/// Individual transaction step
#[derive(Debug)]
struct TransactionStep {
    step_id: String,
    tool: String,
    method: String,
    params: serde_json::Value,
    rollback_method: Option<String>,
    rollback_params: Option<serde_json::Value>,
    completed: bool,
}

/// Transaction status
#[derive(Debug, Clone, PartialEq)]
enum TransactionStatus {
    Active,
    Committed,
    RolledBack,
    Failed,
}

impl CrossToolOrchestrator {
    /// Create a new cross-tool orchestrator
    pub fn new(
        mcp_manager: Arc<McpManager>,
        tool_registry: Arc<RwLock<ToolRegistry>>,
    ) -> Self {
        Self {
            mcp_manager,
            tool_registry,
            active_workflows: Arc::new(RwLock::new(HashMap::new())),
            transaction_manager: Arc::new(TransactionManager::new()),
            semaphore: Arc::new(Semaphore::new(10)), // Max 10 concurrent workflows
        }
    }

    /// Start the orchestrator
    pub async fn start(&self) -> Result<()> {
        info!("Cross-tool orchestrator started");
        Ok(())
    }

    /// Execute a workflow
    #[instrument(skip(self))]
    pub async fn execute_workflow(&self, workflow: Workflow) -> Result<WorkflowResult> {
        // Acquire semaphore permit
        let _permit = self.semaphore.acquire().await
            .map_err(|e| McpError::Internal(format!("Failed to acquire permit: {}", e)))?;
        
        let workflow_id = workflow.id.clone();
        let start_time = Instant::now();
        
        // Initialize workflow state
        let mut state = WorkflowState {
            workflow: workflow.clone(),
            status: WorkflowStatus::Running,
            current_step: None,
            step_results: HashMap::new(),
            start_time,
            end_time: None,
            transaction_id: None,
        };
        
        // Start transaction if needed
        if matches!(workflow.transaction_mode, TransactionMode::Strict | TransactionMode::Saga) {
            let tx_id = Uuid::new_v4().to_string();
            self.transaction_manager.begin_transaction(&tx_id).await?;
            state.transaction_id = Some(tx_id);
        }
        
        // Store state
        self.active_workflows.write().await.insert(workflow_id.clone(), state);
        
        // Execute workflow with timeout
        let result = timeout(workflow.timeout, self.execute_workflow_steps(&workflow_id)).await;
        
        // Handle result
        match result {
            Ok(Ok(())) => {
                self.complete_workflow(&workflow_id, WorkflowStatus::Completed).await?;
            },
            Ok(Err(e)) => {
                error!("Workflow {} failed: {}", workflow_id, e);
                self.handle_workflow_failure(&workflow_id, e).await?;
            },
            Err(_) => {
                error!("Workflow {} timed out", workflow_id);
                self.handle_workflow_failure(&workflow_id, McpError::Timeout("Workflow timeout".to_string())).await?;
            }
        }
        
        // Get final state
        let final_state = self.active_workflows.read().await
            .get(&workflow_id)
            .cloned();
        
        if let Some(state) = final_state {
            Ok(self.build_workflow_result(state))
        } else {
            Err(McpError::Internal("Workflow state lost".to_string()))
        }
    }

    /// Execute workflow steps
    async fn execute_workflow_steps(&self, workflow_id: &str) -> Result<()> {
        let workflow = {
            let workflows = self.active_workflows.read().await;
            workflows.get(workflow_id)
                .ok_or_else(|| McpError::NotFound("Workflow not found".to_string()))?
                .workflow
                .clone()
        };
        
        // Build execution plan
        let execution_plan = self.build_execution_plan(&workflow)?;
        
        // Execute steps according to plan
        for stage in execution_plan {
            self.execute_stage(workflow_id, stage).await?;
        }
        
        Ok(())
    }

    /// Build execution plan from workflow steps
    fn build_execution_plan(&self, workflow: &Workflow) -> Result<Vec<Vec<String>>> {
        let mut plan = Vec::new();
        let mut completed = HashSet::new();
        let mut remaining: HashSet<_> = workflow.steps.iter().map(|s| s.id.clone()).collect();
        
        while !remaining.is_empty() {
            let mut stage = Vec::new();
            
            for step_id in remaining.clone() {
                let step = workflow.steps.iter()
                    .find(|s| s.id == step_id)
                    .ok_or_else(|| McpError::Internal("Step not found".to_string()))?;
                
                // Check if all dependencies are completed
                if step.dependencies.iter().all(|dep| completed.contains(dep)) {
                    stage.push(step_id.clone());
                    remaining.remove(&step_id);
                }
            }
            
            if stage.is_empty() && !remaining.is_empty() {
                return Err(McpError::ValidationError("Circular dependency detected".to_string()));
            }
            
            for step_id in &stage {
                completed.insert(step_id.clone());
            }
            
            if !stage.is_empty() {
                plan.push(stage);
            }
        }
        
        Ok(plan)
    }

    /// Execute a stage of parallel steps
    async fn execute_stage(&self, workflow_id: &str, stage: Vec<String>) -> Result<()> {
        let futures: Vec<_> = stage.into_iter()
            .map(|step_id| self.execute_step(workflow_id, step_id))
            .collect();
        
        let results = join_all(futures).await;
        
        // Check for failures
        for result in results {
            result?;
        }
        
        Ok(())
    }

    /// Execute a single workflow step
    async fn execute_step(&self, workflow_id: &str, step_id: String) -> Result<()> {
        let (workflow, step) = {
            let workflows = self.active_workflows.read().await;
            let state = workflows.get(workflow_id)
                .ok_or_else(|| McpError::NotFound("Workflow not found".to_string()))?;
            
            let step = state.workflow.steps.iter()
                .find(|s| s.id == step_id)
                .ok_or_else(|| McpError::NotFound("Step not found".to_string()))?
                .clone();
            
            (state.workflow.clone(), step)
        };
        
        // Update current step
        {
            let mut workflows = self.active_workflows.write().await;
            if let Some(state) = workflows.get_mut(workflow_id) {
                state.current_step = Some(step_id.clone());
            }
        }
        
        // Check condition
        if let Some(condition) = &step.condition {
            if !self.evaluate_condition(workflow_id, condition).await? {
                self.record_step_result(workflow_id, StepResult {
                    step_id,
                    status: StepStatus::Skipped,
                    output: None,
                    error: None,
                    duration_ms: 0,
                    attempts: 0,
                }).await;
                return Ok(());
            }
        }
        
        // Execute with retry
        let result = self.execute_step_with_retry(workflow_id, &step).await;
        
        match result {
            Ok(output) => {
                self.record_step_result(workflow_id, StepResult {
                    step_id,
                    status: StepStatus::Completed,
                    output: Some(output),
                    error: None,
                    duration_ms: 0, // TODO: Track duration
                    attempts: 1, // TODO: Track attempts
                }).await;
                Ok(())
            },
            Err(e) => {
                self.handle_step_error(workflow_id, &step, e).await
            }
        }
    }

    /// Execute step with retry policy
    async fn execute_step_with_retry(
        &self,
        workflow_id: &str,
        step: &WorkflowStep,
    ) -> Result<serde_json::Value> {
        let retry_policy = {
            let workflows = self.active_workflows.read().await;
            workflows.get(workflow_id)
                .map(|s| s.workflow.retry_policy.clone())
                .unwrap_or_default()
        };
        
        let mut attempts = 0;
        let mut delay = retry_policy.initial_delay_ms;
        
        loop {
            attempts += 1;
            
            // Prepare parameters with data from previous steps
            let params = self.prepare_step_parameters(workflow_id, step).await?;
            
            // Execute tool
            match self.execute_tool(&step.tool, &step.method, &params).await {
                Ok(result) => {
                    // Apply transformation if needed
                    if let Some(transform) = &step.transform {
                        return self.apply_transform(result, transform);
                    }
                    return Ok(result);
                },
                Err(e) => {
                    if attempts >= retry_policy.max_attempts {
                        return Err(e);
                    }
                    
                    warn!("Step {} attempt {} failed: {}, retrying in {}ms",
                          step.id, attempts, e, delay);
                    
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    
                    // Exponential backoff
                    delay = (delay as f32 * retry_policy.exponential_base) as u64;
                    delay = delay.min(retry_policy.max_delay_ms);
                }
            }
        }
    }

    /// Prepare step parameters with data from previous steps
    async fn prepare_step_parameters(
        &self,
        workflow_id: &str,
        step: &WorkflowStep,
    ) -> Result<serde_json::Value> {
        let mut params = step.parameters.clone();
        
        // Replace template variables with actual values from previous steps
        if let serde_json::Value::Object(ref mut map) = params {
            let workflows = self.active_workflows.read().await;
            let state = workflows.get(workflow_id)
                .ok_or_else(|| McpError::NotFound("Workflow not found".to_string()))?;
            
            for (key, value) in map.iter_mut() {
                if let serde_json::Value::String(s) = value {
                    if s.starts_with("{{") && s.ends_with("}}") {
                        let var_name = s.trim_start_matches("{{").trim_end_matches("}}").trim();
                        if let Some(replacement) = self.resolve_variable(var_name, &state.step_results) {
                            *value = replacement;
                        }
                    }
                }
            }
        }
        
        Ok(params)
    }

    /// Resolve a template variable
    fn resolve_variable(
        &self,
        var_name: &str,
        step_results: &HashMap<String, StepResult>,
    ) -> Option<serde_json::Value> {
        // Parse variable format: step_id.path.to.value
        let parts: Vec<&str> = var_name.split('.').collect();
        if parts.is_empty() {
            return None;
        }
        
        let step_id = parts[0];
        if let Some(result) = step_results.get(step_id) {
            if let Some(output) = &result.output {
                // Navigate through the JSON structure
                let mut current = output;
                for part in &parts[1..] {
                    match current {
                        serde_json::Value::Object(map) => {
                            if let Some(next) = map.get(*part) {
                                current = next;
                            } else {
                                return None;
                            }
                        },
                        serde_json::Value::Array(arr) => {
                            if let Ok(index) = part.parse::<usize>() {
                                if let Some(next) = arr.get(index) {
                                    current = next;
                                } else {
                                    return None;
                                }
                            } else {
                                return None;
                            }
                        },
                        _ => return None,
                    }
                }
                return Some(current.clone());
            }
        }
        
        None
    }

    /// Execute a tool through MCP
    async fn execute_tool(
        &self,
        tool: &str,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let registry = self.mcp_manager.registry().read().await;
        let server = registry.get_server_by_type(tool)
            .ok_or_else(|| McpError::ServerNotFound(tool.to_string()))?;
        
        server.execute_tool(method, params).await
    }

    /// Apply data transformation
    fn apply_transform(
        &self,
        data: serde_json::Value,
        transform: &DataTransform,
    ) -> Result<serde_json::Value> {
        match transform {
            DataTransform::JsonPath(path) => {
                // TODO: Implement JSONPath
                Ok(data)
            },
            DataTransform::Jq(query) => {
                // TODO: Implement JQ transformation
                Ok(data)
            },
            DataTransform::Custom(func) => {
                // TODO: Implement custom functions
                Ok(data)
            },
            DataTransform::Map(mapping) => {
                let mut result = serde_json::Map::new();
                if let serde_json::Value::Object(map) = data {
                    for (from, to) in mapping {
                        if let Some(value) = map.get(from) {
                            result.insert(to.clone(), value.clone());
                        }
                    }
                }
                Ok(serde_json::Value::Object(result))
            },
        }
    }

    /// Evaluate step condition
    async fn evaluate_condition(
        &self,
        workflow_id: &str,
        condition: &StepCondition,
    ) -> Result<bool> {
        // TODO: Implement expression evaluation
        // For now, always return true
        Ok(true)
    }

    /// Handle step error
    async fn handle_step_error(
        &self,
        workflow_id: &str,
        step: &WorkflowStep,
        error: McpError,
    ) -> Result<()> {
        match &step.error_handler {
            ErrorHandler::Fail => {
                self.record_step_result(workflow_id, StepResult {
                    step_id: step.id.clone(),
                    status: StepStatus::Failed,
                    output: None,
                    error: Some(error.to_string()),
                    duration_ms: 0,
                    attempts: 1,
                }).await;
                Err(error)
            },
            ErrorHandler::Skip => {
                warn!("Step {} failed, skipping: {}", step.id, error);
                self.record_step_result(workflow_id, StepResult {
                    step_id: step.id.clone(),
                    status: StepStatus::Skipped,
                    output: None,
                    error: Some(error.to_string()),
                    duration_ms: 0,
                    attempts: 1,
                }).await;
                Ok(())
            },
            ErrorHandler::Fallback(value) => {
                warn!("Step {} failed, using fallback: {}", step.id, error);
                self.record_step_result(workflow_id, StepResult {
                    step_id: step.id.clone(),
                    status: StepStatus::Completed,
                    output: Some(value.clone()),
                    error: Some(format!("Fallback used: {}", error)),
                    duration_ms: 0,
                    attempts: 1,
                }).await;
                Ok(())
            },
            ErrorHandler::Compensate { tool, method, params } => {
                warn!("Step {} failed, executing compensation: {}", step.id, error);
                match self.execute_tool(tool, method, params).await {
                    Ok(result) => {
                        self.record_step_result(workflow_id, StepResult {
                            step_id: step.id.clone(),
                            status: StepStatus::Compensated,
                            output: Some(result),
                            error: Some(format!("Compensated: {}", error)),
                            duration_ms: 0,
                            attempts: 1,
                        }).await;
                        Ok(())
                    },
                    Err(comp_error) => {
                        error!("Compensation failed: {}", comp_error);
                        Err(error)
                    }
                }
            },
            ErrorHandler::Retry { .. } => {
                // Retry is handled in execute_step_with_retry
                Err(error)
            },
        }
    }

    /// Record step result
    async fn record_step_result(&self, workflow_id: &str, result: StepResult) {
        let mut workflows = self.active_workflows.write().await;
        if let Some(state) = workflows.get_mut(workflow_id) {
            state.step_results.insert(result.step_id.clone(), result);
        }
    }

    /// Complete workflow
    async fn complete_workflow(&self, workflow_id: &str, status: WorkflowStatus) -> Result<()> {
        let mut workflows = self.active_workflows.write().await;
        if let Some(state) = workflows.get_mut(workflow_id) {
            state.status = status;
            state.end_time = Some(Instant::now());
            
            // Commit transaction if needed
            if let Some(tx_id) = &state.transaction_id {
                self.transaction_manager.commit_transaction(tx_id).await?;
            }
        }
        Ok(())
    }

    /// Handle workflow failure
    async fn handle_workflow_failure(&self, workflow_id: &str, error: McpError) -> Result<()> {
        let mut workflows = self.active_workflows.write().await;
        if let Some(state) = workflows.get_mut(workflow_id) {
            state.status = WorkflowStatus::Failed;
            state.end_time = Some(Instant::now());
            
            // Rollback transaction if needed
            if let Some(tx_id) = &state.transaction_id {
                if matches!(state.workflow.transaction_mode, TransactionMode::Strict | TransactionMode::Saga) {
                    state.status = WorkflowStatus::RollingBack;
                    drop(workflows); // Release lock
                    
                    if let Err(rollback_error) = self.transaction_manager.rollback_transaction(tx_id).await {
                        error!("Rollback failed: {}", rollback_error);
                    }
                    
                    // Update status again
                    let mut workflows = self.active_workflows.write().await;
                    if let Some(state) = workflows.get_mut(workflow_id) {
                        state.status = WorkflowStatus::Failed;
                    }
                }
            }
        }
        Ok(())
    }

    /// Build workflow result
    fn build_workflow_result(&self, state: WorkflowState) -> WorkflowResult {
        let duration_ms = state.end_time
            .map(|end| (end - state.start_time).as_millis() as u64)
            .unwrap_or(0);
        
        WorkflowResult {
            workflow_id: state.workflow.id,
            status: match state.status {
                WorkflowStatus::Completed => "completed".to_string(),
                WorkflowStatus::Failed => "failed".to_string(),
                WorkflowStatus::Cancelled => "cancelled".to_string(),
                _ => "unknown".to_string(),
            },
            steps: state.step_results.into_iter()
                .map(|(id, result)| (id, StepResultOutput {
                    status: format!("{:?}", result.status),
                    output: result.output,
                    error: result.error,
                    duration_ms: result.duration_ms,
                    attempts: result.attempts,
                }))
                .collect(),
            duration_ms,
            transaction_id: state.transaction_id,
        }
    }
}

/// Transaction manager implementation
impl TransactionManager {
    fn new() -> Self {
        Self {
            transactions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn begin_transaction(&self, tx_id: &str) -> Result<()> {
        let mut transactions = self.transactions.write().await;
        transactions.insert(tx_id.to_string(), Transaction {
            id: tx_id.to_string(),
            steps: Vec::new(),
            status: TransactionStatus::Active,
        });
        Ok(())
    }

    async fn commit_transaction(&self, tx_id: &str) -> Result<()> {
        let mut transactions = self.transactions.write().await;
        if let Some(tx) = transactions.get_mut(tx_id) {
            tx.status = TransactionStatus::Committed;
        }
        Ok(())
    }

    async fn rollback_transaction(&self, tx_id: &str) -> Result<()> {
        let mut transactions = self.transactions.write().await;
        if let Some(tx) = transactions.get_mut(tx_id) {
            tx.status = TransactionStatus::RolledBack;
            // TODO: Execute rollback actions
        }
        Ok(())
    }
}

/// Workflow execution result
#[derive(Debug, Serialize)]
pub struct WorkflowResult {
    pub workflow_id: String,
    pub status: String,
    pub steps: HashMap<String, StepResultOutput>,
    pub duration_ms: u64,
    pub transaction_id: Option<String>,
}

/// Step result for output
#[derive(Debug, Serialize)]
pub struct StepResultOutput {
    pub status: String,
    pub output: Option<serde_json::Value>,
    pub error: Option<String>,
    pub duration_ms: u64,
    pub attempts: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_manager::config::McpConfig;

    #[tokio::test]
    async fn test_orchestrator_creation() {
        let config = McpConfig::default();
        let mcp_manager = Arc::new(McpManager::new(config));
        let tool_registry = Arc::new(RwLock::new(ToolRegistry::new()));
        let orchestrator = CrossToolOrchestrator::new(mcp_manager, tool_registry);
        
        assert!(orchestrator.start().await.is_ok());
    }

    #[tokio::test]
    async fn test_workflow_execution_plan() {
        let config = McpConfig::default();
        let mcp_manager = Arc::new(McpManager::new(config));
        let tool_registry = Arc::new(RwLock::new(ToolRegistry::new()));
        let orchestrator = CrossToolOrchestrator::new(mcp_manager, tool_registry);
        
        let workflow = Workflow {
            id: "test".to_string(),
            name: "Test Workflow".to_string(),
            description: "Test".to_string(),
            steps: vec![
                WorkflowStep {
                    id: "step1".to_string(),
                    tool: "test".to_string(),
                    method: "test".to_string(),
                    parameters: serde_json::json!({}),
                    dependencies: vec![],
                    condition: None,
                    transform: None,
                    error_handler: ErrorHandler::Fail,
                },
                WorkflowStep {
                    id: "step2".to_string(),
                    tool: "test".to_string(),
                    method: "test".to_string(),
                    parameters: serde_json::json!({}),
                    dependencies: vec!["step1".to_string()],
                    condition: None,
                    transform: None,
                    error_handler: ErrorHandler::Fail,
                },
            ],
            transaction_mode: TransactionMode::None,
            timeout: Duration::from_secs(60),
            retry_policy: RetryPolicy::default(),
        };
        
        let plan = orchestrator.build_execution_plan(&workflow).unwrap();
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0], vec!["step1".to_string()]);
        assert_eq!(plan[1], vec!["step2".to_string()]);
    }
}