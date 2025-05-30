# Immediate Action Plan - CODE Project
[CREATED: 2025-05-30]
[PRIORITY: CRITICAL]

## 🚨 Critical Issues to Fix First (Next 48 Hours)

### 1. Parameter Validation Failures
**Impact**: 64% of Circle of Experts tests failing
**Files to Fix**:
```python
# Priority 1: Fix these files immediately
src/circle_of_experts/core/expert_manager.py         # Line 142-156: Add None checks
src/circle_of_experts/core/query_handler.py         # Line 89-95: Validate query object
src/circle_of_experts/core/response_collector.py    # Line 178-185: Check response format
```

**Quick Fix**:
```python
# Add to each file:
def validate_params(params: dict) -> dict:
    """Validate and sanitize input parameters."""
    required = ['param1', 'param2']  # Adjust per function
    for req in required:
        if req not in params or params[req] is None:
            raise ValueError(f"Missing required parameter: {req}")
    return params
```

### 2. Missing Retry Logic
**Impact**: 50% network test failures
**Add to**:
```python
# Create new file: src/core/retry.py
import time
from functools import wraps
from typing import Callable, Any

def retry_with_backoff(retries: int = 3, delay: float = 1.0):
    """Decorator for retry with exponential backoff."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            for i in range(retries):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    if i == retries - 1:
                        raise
                    wait_time = delay * (2 ** i)
                    await asyncio.sleep(wait_time)
            return None
        return wrapper
    return decorator
```

### 3. Fix Import Errors
**Files with import issues**:
```bash
# Run these commands:
find . -name "*.py" -exec grep -l "from mcp import" {} \; | xargs sed -i 's/from mcp import/from src.mcp import/g'
find . -name "*.py" -exec grep -l "from circle_of_experts import" {} \; | xargs sed -i 's/from circle_of_experts import/from src.circle_of_experts import/g'
```

## 📋 Week 1 Sprint Plan

### Day 1-2: Stop the Bleeding
- [ ] Fix all parameter validation errors
- [ ] Add retry logic to network operations
- [ ] Fix import paths across all modules
- [ ] Get test suite to >50% passing

### Day 3-4: Error Handling
- [ ] Create `src/core/exceptions.py` with custom exceptions
- [ ] Implement consistent error handling pattern
- [ ] Add proper logging to all modules
- [ ] Create error recovery mechanisms

### Day 5-7: Testing & Documentation
- [ ] Fix all backwards compatibility tests
- [ ] Add missing unit tests for MCP servers
- [ ] Update all docstrings
- [ ] Create integration test suite

## 🛠️ Development Setup Fixes

### 1. Environment Setup Script
Create `scripts/dev_setup.py`:
```python
#!/usr/bin/env python3
"""Complete development environment setup."""

import subprocess
import sys
import os

def setup_environment():
    """Set up complete dev environment."""
    steps = [
        ("Creating virtual environment", "python -m venv venv"),
        ("Activating venv", "source venv/bin/activate" if os.name != 'nt' else "venv\\Scripts\\activate"),
        ("Upgrading pip", f"{sys.executable} -m pip install --upgrade pip"),
        ("Installing requirements", f"{sys.executable} -m pip install -r requirements.txt"),
        ("Installing dev requirements", f"{sys.executable} -m pip install -r requirements-dev.txt"),
        ("Building Rust modules", "cd rust_core && maturin develop && cd .."),
        ("Running tests", "pytest tests/ -v"),
    ]
    
    for desc, cmd in steps:
        print(f"\n🔧 {desc}...")
        result = subprocess.run(cmd, shell=True)
        if result.returncode != 0:
            print(f"❌ Failed: {desc}")
            return False
    
    print("\n✅ Development environment ready!")
    return True

if __name__ == "__main__":
    setup_environment()
```

### 2. Quick Test Runner
Create `scripts/quick_test.sh`:
```bash
#!/bin/bash
# Quick test runner for development

echo "🧪 Running quick tests..."

# Only run fast unit tests
pytest tests/unit -v -x --tb=short

# Check critical integration points
pytest tests/integration/test_mcp_system_integration.py::test_basic_flow -v

echo "✅ Quick tests complete"
```

## 🔥 Performance Quick Wins

### 1. Enable Rust Acceleration by Default
```python
# In src/circle_of_experts/__init__.py
import os
os.environ.setdefault('ENABLE_RUST_ACCELERATION', 'true')

# Auto-import Rust modules if available
try:
    from .rust_accelerated import *
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False
    print("⚠️ Rust acceleration not available, using Python fallback")
```

### 2. Connection Pooling
```python
# Add to src/core/connections.py
import aiohttp
from typing import Optional

class ConnectionPool:
    _instance: Optional['ConnectionPool'] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.session = None
        return cls._instance
    
    async def get_session(self) -> aiohttp.ClientSession:
        if self.session is None:
            connector = aiohttp.TCPConnector(limit=100, limit_per_host=30)
            self.session = aiohttp.ClientSession(connector=connector)
        return self.session
```

## 📊 Success Metrics for Week 1

### Must Achieve:
- ✅ 75% of tests passing (up from 30%)
- ✅ <10s test suite execution
- ✅ Zero import errors
- ✅ All examples running without errors

### Should Achieve:
- 📈 90% parameter validation coverage
- 📈 Retry logic on all network calls
- 📈 Consistent error messages
- 📈 Basic performance benchmarks

### Nice to Have:
- 🎯 100% docstring coverage
- 🎯 Type hints on all functions
- 🎯 Automated CI/CD running
- 🎯 Load test results

## 🚀 Quick Start Commands

```bash
# Fix everything and run tests
make fix-all

# If make doesn't work:
python scripts/dev_setup.py
./scripts/quick_test.sh

# Check what's broken:
pytest tests/ -v --tb=short | grep FAILED

# Fix imports:
find . -name "*.py" -exec python -m py_compile {} \;

# Check Rust status:
cd rust_core && cargo test && cd ..
```

## 📝 Daily Checklist

### Every Morning:
1. [ ] Run `git pull` to get latest changes
2. [ ] Run `pytest tests/ -x` to check status
3. [ ] Fix any new test failures
4. [ ] Update this document with progress

### Every Evening:
1. [ ] Commit working code only
2. [ ] Update test results in `test_results.txt`
3. [ ] Document any blockers
4. [ ] Plan next day's priorities

---
**Remember**: Focus on making it WORK first, then make it PRETTY. The goal is a reliable, production-ready system.