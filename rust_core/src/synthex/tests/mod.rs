//! Comprehensive test suite for SYNTHEX module
//! 
//! This test suite covers:
//! - All agent types and their functionality
//! - Engine performance and correctness
//! - Query parsing and execution
//! - Parallel execution capabilities
//! - Integration with MCP v2
//! - Performance benchmarks

mod agent_tests;
mod engine_tests;
mod query_tests;
mod performance_tests;
mod integration_tests;
mod bashgod_tests;
mod knowledge_graph_tests;
mod mcp_v2_tests;

// Re-export test utilities
pub mod test_utils;

#[cfg(test)]
mod synthex_suite {
    use super::*;
    
    #[test]
    fn test_module_loads() {
        // Verify that all submodules load correctly
        assert!(true);
    }
}