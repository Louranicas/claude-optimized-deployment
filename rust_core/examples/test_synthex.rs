//! Simple test of SYNTHEX module compilation

use code_rust_core::synthex::*;

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("Testing SYNTHEX module compilation...");

    // Create configuration
    let config = SynthexConfig::default();
    println!("✓ Created SynthexConfig");

    // Create a search query
    let query = SearchQuery {
        query: "test query".to_string(),
        options: QueryOptions::default(),
        security_context: None,
    };
    println!("✓ Created SearchQuery");

    // Create engine
    let mut engine = SynthexEngine::new(config).await?;
    println!("✓ Created SynthexEngine");

    // Initialize
    engine.initialize().await?;
    println!("✓ Initialized engine");

    println!("\n🎉 SYNTHEX module compiles and initializes successfully!");

    Ok(())
}
