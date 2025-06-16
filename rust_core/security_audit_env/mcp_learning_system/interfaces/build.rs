// Build script for generating Rust code from protobuf definitions

fn main() {
    // Compile protobuf files
    prost_build::compile_protos(
        &["mcp_messages.proto"],
        &["./"]
    ).expect("Failed to compile protobuf files");
    
    println!("cargo:rerun-if-changed=mcp_messages.proto");
}