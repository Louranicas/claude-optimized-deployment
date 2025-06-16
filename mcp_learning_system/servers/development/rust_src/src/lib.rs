use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

pub mod memory_pool;
pub mod code_analyzer;
pub mod project_graph;
pub mod pattern_cache;
pub mod server;

pub use server::DevelopmentMCPServer;
pub use memory_pool::MemoryPool;
pub use code_analyzer::{CodeAnalyzer, CodePattern};
pub use project_graph::ProjectGraph;
pub use pattern_cache::PatternCache;