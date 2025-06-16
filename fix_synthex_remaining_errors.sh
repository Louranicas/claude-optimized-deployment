#!/bin/bash
# Script to fix remaining SYNTHEX compilation errors

echo "Fixing remaining SYNTHEX compilation errors..."

# 1. Fix invalid struct definition syntax (agents::RawResult should just be RawResult)
echo "Fixing RawResult struct definitions..."
sed -i 's/pub struct agents::RawResult/pub struct RawResult/g' rust_core/src/synthex/agents/mod.rs
sed -i 's/pub struct agents::RawResult/pub struct RawResult/g' rust_core/src/synthex/parallel_executor.rs

# 2. Fix RawResult references to use the correct path
echo "Fixing RawResult references..."
# In agents module files, just use RawResult directly
find rust_core/src/synthex/agents -name "*.rs" -exec sed -i 's/agents::RawResult/RawResult/g' {} \;

# 3. Remove duplicate SubQuery struct definition in query_parser.rs
echo "Removing duplicate SubQuery definition..."
# Keep only the use statement, remove the struct definition
sed -i '/^pub struct SubQuery {/,/^}/d' rust_core/src/synthex/query_parser.rs

# 4. Add RawSearchResults to result_aggregator.rs imports
echo "Adding RawSearchResults import..."
sed -i 's/use super::\*;/use super::*;\nuse crate::synthex::parallel_executor::RawSearchResults;/g' rust_core/src/synthex/result_aggregator.rs

# 5. Fix SearchResult import visibility
echo "Fixing SearchResult import..."
sed -i 's/use crate::synthex::result_aggregator::SearchResult;/use crate::synthex::SearchResult;/g' rust_core/src/synthex/performance_optimizer.rs

# 6. Fix SIMD imports - use feature-gated approach
echo "Fixing SIMD with feature gates..."
cat > /tmp/simd_fix.txt << 'EOF'
#[cfg(feature = "simd")]
use std::simd::{f32x8, u8x32};
#[cfg(feature = "simd")]
use std::simd::prelude::{SimdFloat, SimdPartialEq};
EOF

# Replace SIMD imports in performance_optimizer.rs
sed -i '14,15d' rust_core/src/synthex/performance_optimizer.rs
awk 'NR==13 {system("cat /tmp/simd_fix.txt")} 1' rust_core/src/synthex/performance_optimizer.rs > rust_core/src/synthex/performance_optimizer.rs.tmp && mv rust_core/src/synthex/performance_optimizer.rs.tmp rust_core/src/synthex/performance_optimizer.rs

# 7. Add SIMD feature guards around SIMD code
echo "Adding SIMD feature guards..."
# Wrap SIMD-specific code in cfg attributes
sed -i 's/let text_vec = u8x32::from_slice(chunk);/#[cfg(feature = "simd")]\n            let text_vec = u8x32::from_slice(chunk);/g' rust_core/src/synthex/performance_optimizer.rs
sed -i 's/let pattern_vec = u8x32::from_array(pattern_bytes);/#[cfg(feature = "simd")]\n                let pattern_vec = u8x32::from_array(pattern_bytes);/g' rust_core/src/synthex/performance_optimizer.rs
sed -i 's/let mask = text_vec.simd_eq(pattern_vec);/#[cfg(feature = "simd")]\n                let mask = text_vec.simd_eq(pattern_vec);/g' rust_core/src/synthex/performance_optimizer.rs

# 8. Provide non-SIMD fallback
echo "Adding non-SIMD fallback..."
sed -i 's/#[cfg(feature = "simd")]\n            simd_enabled: is_x86_feature_detected!("avx2"),/            #[cfg(feature = "simd")]\n            simd_enabled: is_x86_feature_detected!("avx2"),\n            #[cfg(not(feature = "simd"))]\n            simd_enabled: false,/g' rust_core/src/synthex/performance_optimizer.rs

# 9. Fix missing await in agent metrics access
echo "Fixing missing await calls..."
find rust_core/src/synthex/agents -name "*.rs" -exec sed -i 's/self\.metrics\.write()\.await\.await/self.metrics.write().await/g' {} \;
find rust_core/src/synthex/agents -name "*.rs" -exec sed -i 's/self\.metrics\.read()\.await\.await/self.metrics.read().await/g' {} \;

# Fix file_agent.rs specifically
sed -i 's/self\.metrics\.write()\./self.metrics.write().await./g' rust_core/src/synthex/agents/file_agent.rs
sed -i 's/self\.metrics\.read()\./self.metrics.read().await./g' rust_core/src/synthex/agents/file_agent.rs
sed -i 's/\.await\.clone()/.clone()/g' rust_core/src/synthex/agents/file_agent.rs

# Fix database_agent.rs specifically
sed -i 's/self\.metrics\.write()\./self.metrics.write().await./g' rust_core/src/synthex/agents/database_agent.rs
sed -i 's/self\.metrics\.read()\./self.metrics.read().await./g' rust_core/src/synthex/agents/database_agent.rs
sed -i 's/\.await\.clone()/.clone()/g' rust_core/src/synthex/agents/database_agent.rs

# 10. Add missing Result type alias import for agents using Result<T>
echo "Adding Result type alias imports..."
find rust_core/src/synthex/agents -name "*.rs" -exec sed -i '1i use crate::synthex::Result;' {} \;

echo "Fixes applied. Running cargo check to verify..."
cd rust_core && cargo check 2>&1 | grep -E "^error" | wc -l