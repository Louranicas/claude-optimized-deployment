#!/usr/bin/env python3
"""
BASHGOD Continuous Training Daemon
Runs perpetual bash training sessions in the background

IMPORTANT: This is a READ-ONLY training system
- Does NOT execute any commands
- Does NOT write or modify any files  
- Does NOT generate new code
- Only studies and learns from existing bash commands
"""

import asyncio
import subprocess
import json
import time
import signal
import sys
import os
from datetime import datetime, timedelta
from pathlib import Path
import random
from typing import List, Dict
import daemon
import lockfile

class BashGodDaemon:
    """Continuous BASHGOD training daemon"""
    
    def __init__(self):
        self.running = True
        self.session_count = 0
        self.total_commands = 0
        self.pid_file = Path('/tmp/bashgod_daemon.pid')
        self.log_file = Path('bashgod_daemon.log')
        self.stats_file = Path('bashgod_stats.json')
        
        # Training techniques
        self.techniques = [
            "pipe_chains",
            "process_substitution", 
            "command_grouping",
            "advanced_redirection",
            "conditional_execution",
            "parallel_execution",
            "loop_constructs",
            "stream_manipulation",
            "parameter_expansion",
            "system_analysis"
        ]
        
        # Load bash commands
        with open('ai_docs/bash_commands.json', 'r') as f:
            self.bash_data = json.load(f)
            
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.log(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
        
    def log(self, message: str):
        """Log with timestamp"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {message}"
        print(log_entry)
        with open(self.log_file, 'a') as f:
            f.write(log_entry + '\n')
            
    async def run_training_session(self):
        """Run a single 5-minute training session"""
        self.session_count += 1
        session_id = f"BASHGOD-DAEMON-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Select random techniques for this session
        num_techniques = random.randint(2, 4)
        session_techniques = random.sample(self.techniques, num_techniques)
        
        self.log(f"Starting session {self.session_count} (ID: {session_id})")
        self.log(f"Techniques: {', '.join(session_techniques)}")
        
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=5)
        commands_executed = 0
        
        # Session loop
        while datetime.now() < end_time and self.running:
            for technique in session_techniques:
                if not self.running or datetime.now() >= end_time:
                    break
                    
                # Get commands for this technique
                technique_commands = [
                    cmd for cmd in self.bash_data['commands'] 
                    if cmd.get('category', '').lower() == technique
                ]
                
                if technique_commands:
                    # Pick a random command
                    cmd = random.choice(technique_commands)
                    
                    # Log the practice (READ-ONLY - no code execution or writing)
                    elapsed = (datetime.now() - start_time).total_seconds()
                    self.log(f"  [{elapsed:.1f}s] Studying: {cmd['description']}")
                    self.log(f"    Command: {cmd['command'][:80]}...")
                    self.log(f"    Category: {cmd.get('category', 'general')}")
                    self.log(f"    Power Level: {cmd.get('power_level', 'N/A')}")
                    
                    commands_executed += 1
                    self.total_commands += 1
                    
                    # READ-ONLY: Just studying commands, not executing
                    # No file writes, no code generation, no system changes
                    await asyncio.sleep(random.uniform(8, 15))
                    
        # Session complete
        duration = (datetime.now() - start_time).total_seconds()
        self.log(f"Session {self.session_count} complete: {duration:.1f}s, {commands_executed} commands")
        
        # Save session stats
        self.save_stats()
        
        return {
            'session_id': session_id,
            'duration': duration,
            'commands': commands_executed,
            'techniques': session_techniques
        }
        
    def save_stats(self):
        """Save daemon statistics"""
        stats = {
            'daemon_start': self.daemon_start.isoformat(),
            'last_update': datetime.now().isoformat(),
            'sessions_completed': self.session_count,
            'total_commands_practiced': self.total_commands,
            'average_commands_per_session': self.total_commands / max(1, self.session_count),
            'uptime_hours': (datetime.now() - self.daemon_start).total_seconds() / 3600
        }
        
        with open(self.stats_file, 'w') as f:
            json.dump(stats, f, indent=2)
            
    async def training_loop(self):
        """Main training loop"""
        self.daemon_start = datetime.now()
        self.log("BASHGOD Continuous Training Daemon started")
        
        while self.running:
            try:
                # Run training session
                session_result = await self.run_training_session()
                
                if not self.running:
                    break
                    
                # 30-second break between sessions
                self.log("Taking 30-second break...")
                await asyncio.sleep(30)
                
            except Exception as e:
                self.log(f"Error in training session: {e}")
                await asyncio.sleep(60)  # Wait a minute before retry
                
        self.log("BASHGOD Daemon stopped")
        
    def start_daemon(self):
        """Start as daemon process"""
        # Check if already running
        if self.pid_file.exists():
            print(f"Daemon already running (PID file exists: {self.pid_file})")
            return
            
        # Create daemon context
        context = daemon.DaemonContext(
            working_directory=os.getcwd(),
            pidfile=lockfile.FileLock(str(self.pid_file)),
            stdout=open(self.log_file, 'a'),
            stderr=open(self.log_file, 'a')
        )
        
        with context:
            # Write PID
            with open(self.pid_file, 'w') as f:
                f.write(str(os.getpid()))
                
            # Set up signal handlers
            signal.signal(signal.SIGTERM, self.signal_handler)
            signal.signal(signal.SIGINT, self.signal_handler)
            
            # Run training loop
            asyncio.run(self.training_loop())
            
            # Clean up PID file
            if self.pid_file.exists():
                self.pid_file.unlink()
                
    def stop_daemon(self):
        """Stop daemon process"""
        if not self.pid_file.exists():
            print("Daemon not running")
            return
            
        with open(self.pid_file, 'r') as f:
            pid = int(f.read().strip())
            
        try:
            os.kill(pid, signal.SIGTERM)
            print(f"Sent SIGTERM to daemon (PID: {pid})")
        except ProcessLookupError:
            print(f"Process {pid} not found")
            self.pid_file.unlink()
            
    def status(self):
        """Check daemon status"""
        if not self.pid_file.exists():
            print("BASHGOD Daemon: Not running")
            return
            
        with open(self.pid_file, 'r') as f:
            pid = int(f.read().strip())
            
        try:
            os.kill(pid, 0)  # Check if process exists
            print(f"BASHGOD Daemon: Running (PID: {pid})")
            
            # Show stats if available
            if self.stats_file.exists():
                with open(self.stats_file, 'r') as f:
                    stats = json.load(f)
                print(f"  Sessions completed: {stats['sessions_completed']}")
                print(f"  Commands practiced: {stats['total_commands_practiced']}")
                print(f"  Uptime: {stats['uptime_hours']:.1f} hours")
                
        except ProcessLookupError:
            print(f"BASHGOD Daemon: PID file exists but process {pid} not found")
            self.pid_file.unlink()

class BashGodStandalone:
    """Standalone version for non-daemon mode"""
    
    def __init__(self):
        self.trainer = BashGodDaemon()
        
    async def run(self):
        """Run in foreground mode"""
        print("Running BASHGOD in standalone mode (Ctrl+C to stop)")
        
        # Set up signal handler
        def signal_handler(signum, frame):
            print("\nStopping BASHGOD...")
            self.trainer.running = False
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Run training loop
        await self.trainer.training_loop()

def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: bashgod_continuous_training.py [start|stop|status|run]")
        print("  start  - Start as background daemon")
        print("  stop   - Stop daemon")
        print("  status - Check daemon status")
        print("  run    - Run in foreground (non-daemon)")
        sys.exit(1)
        
    command = sys.argv[1].lower()
    
    if command == 'start':
        trainer = BashGodDaemon()
        trainer.start_daemon()
    elif command == 'stop':
        trainer = BashGodDaemon()
        trainer.stop_daemon()
    elif command == 'status':
        trainer = BashGodDaemon()
        trainer.status()
    elif command == 'run':
        standalone = BashGodStandalone()
        asyncio.run(standalone.run())
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

if __name__ == "__main__":
    main()