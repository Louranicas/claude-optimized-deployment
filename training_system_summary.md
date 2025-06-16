# SYNTHEX & BASHGOD Training System

## Overview

This system consists of two concurrent components for advanced bash command discovery and training:

### 1. SYNTHEX Fleet Deployment (`synthex_bash_discovery.py`)

- Deploys 10 parallel agents, each specialized in a unique category
- Discovers new bash commands not in the existing collection
- Power level 7+ commands only (advanced/expert level)
- Saves discoveries to `ai_docs/04_ADDITIONAL_BASH_COMMANDS.md`

**Agent Categories:**
1. System Performance Monitoring
2. Network Diagnostics & Security
3. Container & Kubernetes Operations
4. Advanced Text Processing
5. System Debugging & Tracing
6. Backup & Recovery Operations
7. Advanced Git Operations
8. System Resource Management
9. Log Analysis & Forensics
10. Advanced Shell Scripting Patterns

### 2. BASHGOD Continuous Training (`bashgod_continuous_training.py`)

- Runs continuous training sessions in a daemon process
- 5-minute training sessions with 30-second breaks
- Randomly selects 2-4 techniques per session
- Logs progress and statistics
- Can be controlled with start/stop/status commands

**Training Techniques:**
- Pipe mastery
- Process substitution
- Advanced redirection
- Parallel execution
- Stream manipulation
- Parameter expansion
- Command grouping
- Conditional logic
- Loop optimization
- Signal handling

## Usage

### Quick Start

Run both systems concurrently:
```bash
./run_concurrent_training.sh
```

### Individual Control

**SYNTHEX Discovery:**
```bash
python3 synthex_bash_discovery.py
```

**BASHGOD Training:**
```bash
# Start daemon
python3 bashgod_continuous_training.py start

# Check status
python3 bashgod_continuous_training.py status

# Stop daemon
python3 bashgod_continuous_training.py stop

# Test single session
python3 bashgod_continuous_training.py test
```

## File Locations

- **Discovered Commands**: `ai_docs/04_ADDITIONAL_BASH_COMMANDS.md`
- **Training Logs**: `logs/bashgod/`
  - Main log: `bashgod_training.log`
  - Session logs: `session_*.log`
  - Statistics: `training_stats.json`
- **PID File**: `/tmp/bashgod_training.pid`

## Monitoring

Watch real-time training progress:
```bash
tail -f logs/bashgod/bashgod_training.log
```

View discovered commands:
```bash
cat ai_docs/04_ADDITIONAL_BASH_COMMANDS.md
```

Check training statistics:
```bash
cat logs/bashgod/training_stats.json | jq
```

## Features

### SYNTHEX Fleet
- Parallel agent deployment using ThreadPoolExecutor
- Duplicate detection against existing commands
- Category-specific command generation
- Power level assessment (7-10)
- Markdown and JSON output formats

### BASHGOD Training
- Continuous loop with automatic breaks
- Session UUID tracking
- Performance statistics tracking
- Technique rotation for comprehensive coverage
- Graceful shutdown handling
- Resource monitoring

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Concurrent Training System              │
├─────────────────────┬───────────────────────────────────┤
│   SYNTHEX Fleet     │      BASHGOD Daemon               │
├─────────────────────┼───────────────────────────────────┤
│ • 10 Parallel Agents│ • Continuous Training Loop        │
│ • Command Discovery │ • 5-min Sessions                  │
│ • Duplicate Check   │ • 30-sec Breaks                   │
│ • Power Level 7+    │ • Random Technique Selection      │
│ • Category Focus    │ • Progress Logging                │
└─────────────────────┴───────────────────────────────────┘
```

## Safety Notes

- BASHGOD training scenarios are simulated (commands are logged but not executed)
- All file operations use safe paths
- Daemon process handles signals gracefully
- PID file prevents multiple instances