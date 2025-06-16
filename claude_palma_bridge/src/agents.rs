// Multi-agent loader + role system
use crate::memory::SharedMemoryStack;
use std::sync::Arc;
use uuid::Uuid;
use dashmap::DashMap;

#[derive(Clone)]
pub struct Agent {
    pub id: String,
    pub role: AgentRole,
    pub status: AgentStatus,
}

#[derive(Clone)]
pub enum AgentRole {
    Claude,
    Palma,
    Bridge,
    Monitor,
}

#[derive(Clone)]
pub enum AgentStatus {
    Active,
    Idle,
    Processing,
    Error(String),
}

impl Agent {
    pub fn new(role: AgentRole) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            role,
            status: AgentStatus::Idle,
        }
    }

    pub async fn run_autonomous_cycle(&mut self, memory: Arc<SharedMemoryStack>) {
        self.status = AgentStatus::Processing;
        
        match self.role {
            AgentRole::Claude => {
                memory.write_tensor(&format!("claude_{}", self.id), "active");
            },
            AgentRole::Palma => {
                memory.write_tensor(&format!("palma_{}", self.id), "active");
            },
            AgentRole::Bridge => {
                memory.write_tensor(&format!("bridge_{}", self.id), "syncing");
            },
            AgentRole::Monitor => {
                let (count, _) = memory.get_memory_stats();
                memory.write_tensor("monitor_tensor_count", &count.to_string());
            },
        }
        
        self.status = AgentStatus::Active;
    }
}

pub struct AgentRegistry {
    agents: Arc<DashMap<String, Agent>>,
}

impl Default for AgentRegistry {
    fn default() -> Self {
        println!("🤖 Agent Registry initialized");
        let registry = Self {
            agents: Arc::new(DashMap::new()),
        };
        
        // Initialize default agents
        let claude_agent = Agent::new(AgentRole::Claude);
        let palma_agent = Agent::new(AgentRole::Palma);
        let bridge_agent = Agent::new(AgentRole::Bridge);
        let monitor_agent = Agent::new(AgentRole::Monitor);
        
        registry.agents.insert(claude_agent.id.clone(), claude_agent);
        registry.agents.insert(palma_agent.id.clone(), palma_agent);
        registry.agents.insert(bridge_agent.id.clone(), bridge_agent);
        registry.agents.insert(monitor_agent.id.clone(), monitor_agent);
        
        registry
    }
}

impl AgentRegistry {
    pub fn all(&self) -> Vec<Agent> {
        self.agents.iter().map(|entry| entry.value().clone()).collect()
    }
    
    pub fn get_agent(&self, id: &str) -> Option<Agent> {
        self.agents.get(id).map(|entry| entry.value().clone())
    }
    
    pub fn count(&self) -> usize {
        self.agents.len()
    }
}