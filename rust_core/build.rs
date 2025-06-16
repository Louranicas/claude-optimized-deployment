// Build script for rust_core
// This ensures all dependencies are properly configured

fn main() {
    // Set up Python configuration for PyO3
    pyo3_build_config::use_pyo3_cfgs();

    // Print cargo directives
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=Cargo.toml");

    // Set feature flags
    if cfg!(target_arch = "x86_64") || cfg!(target_arch = "aarch64") {
        println!("cargo:rustc-cfg=feature=\"simd\"");
    }
}
