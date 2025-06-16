// Claude-Aware Agentic Task Orchestrator
use crate::memory::SharedMemoryStack;
use crate::agents::AgentRegistry;
use tokio::time::{interval, Duration};
use std::sync::Arc;

pub struct TaskOrchestrator {
    memory: Arc<SharedMemoryStack>,
    agents: Arc<AgentRegistry>,
    cycle_count: u64,
}

impl TaskOrchestrator {
    pub fn new(memory: Arc<SharedMemoryStack>, agents: Arc<AgentRegistry>) -> Self {
        println!("⚙️ Task Orchestrator initialized");
        Self { 
            memory, 
            agents,
            cycle_count: 0,
        }
    }

    pub async fn bootstrap_loop(&mut self) {
        println!("🔄 Starting bootstrap loop...");
        let mut task_interval = interval(Duration::from_secs(10));
        
        loop {
            task_interval.tick().await;
            self.cycle_count += 1;
            self.sync_tasks().await;
            
            if self.cycle_count % 6 == 0 {
                self.report_status().await;
            }
        }
    }

    async fn sync_tasks(&self) {
        let agents = self.agents.all();
        println!("🔄 Syncing {} agents (cycle {})", agents.len(), self.cycle_count);
        
        for mut agent in agents {
            agent.run_autonomous_cycle(self.memory.clone()).await;
        }
        
        // Update orchestrator status
        self.memory.write_tensor("orchestrator_cycle", &self.cycle_count.to_string());
        self.memory.write_tensor("orchestrator_status", "running");
    }
    
    async fn report_status(&self) {
        let (tensor_count, _) = self.memory.get_memory_stats();
        let agent_count = self.agents.count();
        
        println!("📊 Bridge Status Report:");
        println!("   • Agents: {}", agent_count);
        println!("   • Memory tensors: {}", tensor_count);
        println!("   • Cycles completed: {}", self.cycle_count);
        println!("   • System: Operational");
    }
}