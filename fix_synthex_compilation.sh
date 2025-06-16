#!/bin/bash
# Script to fix SYNTHEX compilation errors

echo "Fixing SYNTHEX compilation errors..."

# 1. Fix SIMD imports
echo "Fixing SIMD imports..."
find rust_core/src/synthex -name "*.rs" -exec sed -i 's/use std::simd::{f32x8, u8x32, SimdFloat, SimdPartialEq};/use std::simd::{f32x8, u8x32};\nuse std::simd::prelude::{SimdFloat, SimdPartialEq};/g' {} \;

# 2. Fix Result type usage - change Result<T, Box<dyn std::error::Error>> to just Result<T>
echo "Fixing Result type usage..."
find rust_core/src/synthex -name "*.rs" -exec sed -i 's/Result<\([^,]*\), Box<dyn std::error::Error>>/Result<\1>/g' {} \;

# 3. Add hashmap! macro at the top of files that use it
echo "Adding hashmap! macro..."
cat > /tmp/hashmap_macro.txt << 'EOF'
// Helper macro for creating HashMaps
macro_rules! hashmap {
    (@single $($x:tt)*) => (());
    (@count $($rest:expr),*) => (<[()]>::len(&[$(hashmap!(@single $rest)),*]));
    
    ($($key:expr => $value:expr,)+) => { hashmap!($($key => $value),+) };
    ($($key:expr => $value:expr),*) => {
        {
            let _cap = hashmap!(@count $($key),*);
            let mut _map = ::std::collections::HashMap::with_capacity(_cap);
            $(
                let _ = _map.insert($key, $value);
            )*
            _map
        }
    };
}

EOF

# Add macro to files that need it
for file in rust_core/src/synthex/agents/{web_agent,file_agent}.rs; do
    if grep -q "hashmap!" "$file" && ! grep -q "macro_rules! hashmap" "$file"; then
        # Insert after the use statements
        awk '/^use / {p=1} p && /^$/ && !done {print; system("cat /tmp/hashmap_macro.txt"); done=1; next} 1' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
    fi
done

# 4. Fix missing .await calls
echo "Fixing missing .await calls..."
# Fix patterns like: self.metrics.write().total_searches -> self.metrics.write().await.total_searches
find rust_core/src/synthex -name "*.rs" -exec sed -i 's/\(self\.metrics\.\(read\|write\)()\)\.\([a-z_]*\)/\1.await.\3/g' {} \;

# 5. Fix SubQuery imports
echo "Fixing SubQuery imports..."
# Add proper imports where SubQuery is used
find rust_core/src/synthex -name "*.rs" -exec sed -i 's/use super::\*;/use super::*;\nuse crate::synthex::query::SubQuery;/g' {} \;

# 6. Fix RawResult type references
echo "Fixing RawResult references..."
# Import RawResult from agents module where needed
find rust_core/src/synthex -name "*.rs" -exec sed -i 's/RawResult/agents::RawResult/g' {} \;
# But not in the agents module itself
sed -i 's/agents::agents::RawResult/RawResult/g' rust_core/src/synthex/agents/*.rs

# 7. Fix ExecutionPlan import
echo "Fixing ExecutionPlan import..."
sed -i 's/use crate::synthex::parallel_executor::ExecutionPlan;/use crate::synthex::query_parser::ExecutionPlan;/g' rust_core/src/synthex/performance_optimizer.rs

# 8. Fix HttpConnector type
echo "Fixing HttpConnector type..."
find rust_core/src/synthex -name "*.rs" -exec sed -i 's/hyper::client::HttpConnector/hyper::client::connect::HttpConnector/g' {} \;

# 9. Remove duplicate macro definitions
echo "Removing duplicate macro definitions..."
# Keep only the first hashmap! macro definition in each file
for file in rust_core/src/synthex/agents/*.rs; do
    if [ -f "$file" ]; then
        awk '/^macro_rules! hashmap/ && !seen {seen=1; print; getline; while (/^[[:space:]]/ || /^}/) {print; if (/^}/) break; getline}} !(/^macro_rules! hashmap/) {print}' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
    fi
done

# 10. Fix From<&str> for SynthexError
echo "Adding From<&str> implementation for SynthexError..."
cat >> rust_core/src/synthex/mod.rs << 'EOF'

impl From<&str> for SynthexError {
    fn from(s: &str) -> Self {
        SynthexError::SearchError(s.to_string())
    }
}

impl From<String> for SynthexError {
    fn from(s: String) -> Self {
        SynthexError::SearchError(s)
    }
}
EOF

echo "Fixes applied. Running cargo check to verify..."
cd rust_core && cargo check 2>&1 | grep -E "^error" | wc -l