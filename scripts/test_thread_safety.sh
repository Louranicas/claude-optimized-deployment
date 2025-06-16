#!/bin/bash
# Thread Safety Testing Script
# This script runs comprehensive thread safety tests with various sanitizers

set -e

echo "🔍 Thread Safety Testing Suite"
echo "============================="

PROJECT_ROOT="${1:-$(pwd)}"
cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
PASSED=0
FAILED=0

# Function to run test with specific sanitizer
run_sanitizer_test() {
    local test_name="$1"
    local sanitizer_flag="$2"
    local test_pattern="${3:-}"
    
    echo -e "\n${YELLOW}Running $test_name...${NC}"
    
    if RUSTFLAGS="$sanitizer_flag" cargo test $test_pattern -- --test-threads=1 --nocapture 2>&1 | tee "/tmp/${test_name}.log"; then
        echo -e "${GREEN}✅ $test_name passed${NC}"
        ((PASSED++))
    else
        echo -e "${RED}❌ $test_name failed${NC}"
        ((FAILED++))
        
        # Extract sanitizer warnings
        if grep -q "WARNING:" "/tmp/${test_name}.log"; then
            echo -e "${RED}Sanitizer warnings found:${NC}"
            grep "WARNING:" "/tmp/${test_name}.log" | head -10
        fi
    fi
}

# 1. Thread Sanitizer Tests
if rustc --print target-list | grep -q "x86_64-unknown-linux-gnu"; then
    echo -e "\n${YELLOW}1. Thread Sanitizer Tests${NC}"
    
    # Build with thread sanitizer
    export RUSTFLAGS="-Z sanitizer=thread"
    export RUST_TEST_THREADS=1
    
    # Run specific thread safety tests
    cargo +nightly test --target x86_64-unknown-linux-gnu thread_safety 2>&1 | tee /tmp/tsan.log || true
    
    # Check for data races
    if grep -q "WARNING: ThreadSanitizer: data race" /tmp/tsan.log; then
        echo -e "${RED}❌ Data races detected!${NC}"
        grep -A 10 "WARNING: ThreadSanitizer: data race" /tmp/tsan.log | head -50
        ((FAILED++))
    else
        echo -e "${GREEN}✅ No data races detected${NC}"
        ((PASSED++))
    fi
else
    echo -e "${YELLOW}Thread sanitizer not available on this platform${NC}"
fi

# 2. Loom Tests (if available)
echo -e "\n${YELLOW}2. Loom Concurrency Tests${NC}"
if cargo tree | grep -q "loom"; then
    LOOM_MAX_THREADS=4 LOOM_CHECKPOINT_INTERVAL=100 cargo test --features loom loom_tests 2>&1 | tee /tmp/loom.log || true
    
    if grep -q "panicked" /tmp/loom.log; then
        echo -e "${RED}❌ Loom tests found issues${NC}"
        ((FAILED++))
    else
        echo -e "${GREEN}✅ Loom tests passed${NC}"
        ((PASSED++))
    fi
else
    echo "Loom not found in dependencies, skipping..."
fi

# 3. Miri Tests (for undefined behavior)
echo -e "\n${YELLOW}3. Miri Tests (Undefined Behavior)${NC}"
if command -v cargo-miri &> /dev/null; then
    cargo +nightly miri test thread_safety 2>&1 | tee /tmp/miri.log || true
    
    if grep -q "error: " /tmp/miri.log; then
        echo -e "${RED}❌ Miri found undefined behavior${NC}"
        grep "error: " /tmp/miri.log | head -10
        ((FAILED++))
    else
        echo -e "${GREEN}✅ No undefined behavior detected${NC}"
        ((PASSED++))
    fi
else
    echo "Miri not installed, run: rustup +nightly component add miri"
fi

# 4. Static Analysis with Clippy
echo -e "\n${YELLOW}4. Clippy Thread Safety Lints${NC}"
cargo clippy -- \
    -W clippy::mutex_atomic \
    -W clippy::mutex_integer \
    -W clippy::non_send_fields_in_send_ty \
    -W clippy::rc_mutex \
    -W clippy::await_holding_lock \
    -W clippy::await_holding_refcell_ref 2>&1 | tee /tmp/clippy.log

if grep -q "warning:" /tmp/clippy.log; then
    echo -e "${RED}❌ Clippy found thread safety issues${NC}"
    ((FAILED++))
else
    echo -e "${GREEN}✅ Clippy checks passed${NC}"
    ((PASSED++))
fi

# 5. Custom Thread Safety Tests
echo -e "\n${YELLOW}5. Custom Thread Safety Tests${NC}"

# Create a test for common patterns
cat > /tmp/thread_safety_test.rs << 'EOF'
#[cfg(test)]
mod thread_safety_tests {
    use std::sync::{Arc, Mutex, RwLock, atomic::{AtomicUsize, Ordering}};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_no_deadlocks() {
        let lock1 = Arc::new(Mutex::new(0));
        let lock2 = Arc::new(Mutex::new(0));
        
        let mut handles = vec![];
        
        // Thread 1: lock1 then lock2
        {
            let l1 = lock1.clone();
            let l2 = lock2.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    let _g1 = l1.lock().unwrap();
                    thread::yield_now();
                    let _g2 = l2.lock().unwrap();
                }
            }));
        }
        
        // Thread 2: Always same order (no deadlock)
        {
            let l1 = lock1.clone();
            let l2 = lock2.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    let _g1 = l1.lock().unwrap();
                    thread::yield_now();
                    let _g2 = l2.lock().unwrap();
                }
            }));
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_atomic_operations() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];
        
        for _ in 0..10 {
            let counter = counter.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        assert_eq!(counter.load(Ordering::SeqCst), 10000);
    }

    #[test]
    fn test_send_sync_safety() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        
        // These should compile
        assert_send::<Arc<Mutex<String>>>();
        assert_sync::<Arc<Mutex<String>>>();
        assert_send::<Arc<RwLock<Vec<u8>>>>();
        assert_sync::<Arc<RwLock<Vec<u8>>>>();
    }
}
EOF

# Run the custom test
rustc /tmp/thread_safety_test.rs --test -o /tmp/thread_test && /tmp/thread_test || true

# 6. Stress Testing
echo -e "\n${YELLOW}6. Concurrent Stress Tests${NC}"
cargo test stress_test -- --test-threads=8 --nocapture 2>&1 | tee /tmp/stress.log || true

if grep -q "test result: ok" /tmp/stress.log; then
    echo -e "${GREEN}✅ Stress tests passed${NC}"
    ((PASSED++))
else
    echo -e "${RED}❌ Stress tests failed${NC}"
    ((FAILED++))
fi

# 7. Memory Ordering Analysis
echo -e "\n${YELLOW}7. Memory Ordering Analysis${NC}"

# Check for relaxed ordering that might be problematic
echo "Checking for potentially weak memory orderings..."
rg "Ordering::Relaxed" --type rust -A 2 -B 2 | head -20

# Count different ordering types
echo -e "\nMemory ordering usage:"
echo -n "  Relaxed: "; rg "Ordering::Relaxed" --type rust -c | wc -l
echo -n "  Acquire: "; rg "Ordering::Acquire" --type rust -c | wc -l
echo -n "  Release: "; rg "Ordering::Release" --type rust -c | wc -l
echo -n "  AcqRel:  "; rg "Ordering::AcqRel" --type rust -c | wc -l
echo -n "  SeqCst:  "; rg "Ordering::SeqCst" --type rust -c | wc -l

# 8. Lock Analysis
echo -e "\n${YELLOW}8. Lock Usage Analysis${NC}"

# Find potential lock ordering issues
echo "Checking for multiple lock acquisitions..."
rg "\.lock\(\).*\.lock\(\)" --type rust | head -10

# Check for locks held across await points
echo -e "\nChecking for locks held across await points..."
rg "\.lock\(\).*\.await" --type rust -A 3 -B 3 | head -20

# Summary
echo -e "\n${YELLOW}===== Thread Safety Test Summary =====${NC}"
echo -e "Tests passed: ${GREEN}$PASSED${NC}"
echo -e "Tests failed: ${RED}$FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}✅ All thread safety tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}❌ Some thread safety tests failed!${NC}"
    exit 1
fi