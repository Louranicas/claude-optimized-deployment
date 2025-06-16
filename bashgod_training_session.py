#!/usr/bin/env python3
"""
BASHGOD Training Session
Real-time bash command practice using SYNTHEX findings
"""

import asyncio
import subprocess
import time
from datetime import datetime, timedelta
import json
from pathlib import Path
import random

class BashGod:
    """The BASHGOD - Master of Command Line Synergy"""
    
    def __init__(self):
        self.start_time = None
        self.session_duration = 300  # 5 minutes in seconds
        self.commands_executed = 0
        self.techniques_practiced = set()
        self.discoveries = []
        
        # Load SYNTHEX findings
        with open('ai_docs/bash_commands.json', 'r') as f:
            self.synthex_data = json.load(f)
        self.advanced_commands = self.synthex_data['commands']
        
    async def start_training(self):
        """Begin the 5-minute training session"""
        self.start_time = datetime.now()
        end_time = self.start_time + timedelta(seconds=self.session_duration)
        
        print(f"\n{'='*80}")
        print(f"BASHGOD TRAINING SESSION INITIATED")
        print(f"{'='*80}")
        print(f"Start Time: {self.start_time.strftime('%H:%M:%S')}")
        print(f"End Time: {end_time.strftime('%H:%M:%S')}")
        print(f"Duration: 5 minutes")
        print(f"Mission: Practice advanced bash techniques on the codebase")
        print(f"{'='*80}\n")
        
        # Start real-time counter
        counter_task = asyncio.create_task(self.display_counter())
        
        # Execute training sequences
        training_task = asyncio.create_task(self.execute_training())
        
        # Wait for completion
        await asyncio.gather(counter_task, training_task)
        
        # Display results
        self.display_summary()
        
    async def display_counter(self):
        """Display real-time counter"""
        while True:
            elapsed = (datetime.now() - self.start_time).total_seconds()
            remaining = self.session_duration - elapsed
            
            if remaining <= 0:
                print(f"\r[TIME'S UP!] Session Complete!", end='', flush=True)
                break
                
            minutes = int(remaining // 60)
            seconds = int(remaining % 60)
            progress = int((elapsed / self.session_duration) * 50)
            progress_bar = '█' * progress + '░' * (50 - progress)
            
            print(f"\r[{progress_bar}] {minutes:02d}:{seconds:02d} remaining | Commands: {self.commands_executed}", 
                  end='', flush=True)
            
            await asyncio.sleep(0.1)
            
    async def execute_training(self):
        """Execute bash command practice sequences"""
        sequences = [
            self.practice_pipe_chains,
            self.practice_process_substitution,
            self.practice_advanced_searching,
            self.practice_parallel_execution,
            self.practice_stream_manipulation,
            self.practice_codebase_analysis,
            self.practice_performance_analysis,
            self.practice_security_scanning,
            self.practice_documentation_search,
            self.practice_git_archaeology
        ]
        
        sequence_duration = 30  # 30 seconds per technique
        
        for sequence in sequences:
            if (datetime.now() - self.start_time).total_seconds() >= self.session_duration:
                break
                
            await sequence()
            await asyncio.sleep(1)  # Brief pause between sequences
            
    async def execute_command(self, command: str, description: str):
        """Execute a bash command and log results"""
        self.commands_executed += 1
        
        # Log the practice
        elapsed = (datetime.now() - self.start_time).total_seconds()
        print(f"\n\n[{elapsed:.1f}s] Executing: {description}")
        print(f"Command: {command}")
        
        try:
            # Execute command with shorter timeout to prevent blocking
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True,
                timeout=2
            )
            
            # Show results (truncated)
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                print(f"Output ({len(lines)} lines):")
                for line in lines[:5]:  # Show first 5 lines
                    print(f"  {line}")
                if len(lines) > 5:
                    print(f"  ... and {len(lines) - 5} more lines")
                    
            self.discoveries.append({
                'time': elapsed,
                'description': description,
                'command': command,
                'lines_output': len(lines) if result.stdout else 0
            })
            
        except subprocess.TimeoutExpired:
            print("  [Timeout - command took too long]")
        except Exception as e:
            print(f"  [Error: {e}]")
            
    async def practice_pipe_chains(self):
        """Practice advanced pipe chains from SYNTHEX findings"""
        self.techniques_practiced.add("Pipe Chains")
        
        # Find Python files with potential issues
        await self.execute_command(
            "find src -name '*.py' | xargs grep -l 'TODO\\|FIXME\\|XXX' | while read f; do echo \"=== $f ===\"; grep -n -C 2 'TODO\\|FIXME\\|XXX' \"$f\"; done | head -20",
            "Complex pipe chain: Find all TODO/FIXME comments with context"
        )
        
        # Analyze code complexity
        await self.execute_command(
            "find src -name '*.py' -type f | xargs wc -l | sort -nr | head -20 | awk '{sum+=$1; print $0} END {print \"Total lines in top 20 files: \" sum}'",
            "Pipe chain: Analyze largest Python files and sum their lines"
        )
        
    async def practice_process_substitution(self):
        """Practice process substitution techniques"""
        self.techniques_practiced.add("Process Substitution")
        
        # Compare file structures
        await self.execute_command(
            "diff <(ls -la src/auth/ | awk '{print $9}' | sort) <(ls -la src/mcp/ | awk '{print $9}' | sort)",
            "Process substitution: Compare files in auth vs mcp directories"
        )
        
        # Find unique imports
        await self.execute_command(
            "comm -23 <(grep -h '^import\\|^from' src/auth/*.py | sort -u) <(grep -h '^import\\|^from' src/mcp/*.py | sort -u) | head -10",
            "Process substitution: Find imports unique to auth module"
        )
        
    async def practice_advanced_searching(self):
        """Practice advanced search patterns"""
        self.techniques_practiced.add("Advanced Searching")
        
        # Multi-pattern search with context
        await self.execute_command(
            "grep -r -E '(async def|await|asyncio)' src --include='*.py' | grep -v test | cut -d: -f1 | uniq -c | sort -nr | head -10",
            "Advanced search: Find files with most async operations"
        )
        
        # Security pattern search
        await self.execute_command(
            "find src -name '*.py' -exec grep -l 'password\\|secret\\|key\\|token' {} + | xargs -I {} sh -c 'echo \"=== {} ===\"; grep -n \"password\\|secret\\|key\\|token\" \"{}\" | grep -v \"^[[:space:]]*#\"' | head -30",
            "Security search: Find potential sensitive data patterns"
        )
        
    async def practice_parallel_execution(self):
        """Practice parallel execution patterns"""
        self.techniques_practiced.add("Parallel Execution")
        
        # Parallel file analysis
        await self.execute_command(
            "find src -name '*.py' -type f | head -10 | xargs -P 4 -I {} sh -c 'echo \"Analyzing {}\"; grep -c \"^class\" {} | xargs printf \"{}: %d classes\\n\"'",
            "Parallel execution: Count classes in multiple files simultaneously"
        )
        
        # Parallel syntax checking (simulated)
        await self.execute_command(
            "find src -name '*.py' | head -5 | xargs -P 3 -I {} bash -c 'echo \"Checking {}\"; python -m py_compile {} 2>&1 || echo \"Syntax error in {}\"'",
            "Parallel syntax validation of Python files"
        )
        
    async def practice_stream_manipulation(self):
        """Practice stream manipulation"""
        self.techniques_practiced.add("Stream Manipulation")
        
        # Real-time log analysis simulation
        await self.execute_command(
            "tail -n 50 synthex_enterprise_security_framework.py | grep -E '(finding|threat|security)' | awk '{print NR \": \" $0}' | sed 's/finding/[FINDING]/g'",
            "Stream manipulation: Process security framework with multiple filters"
        )
        
        # Multi-stream processing
        await self.execute_command(
            "cat src/synthex/security.py | tee >(grep -c 'def' | xargs echo 'Functions:') >(grep -c 'class' | xargs echo 'Classes:') >(wc -l | xargs echo 'Total lines:') > /dev/null",
            "Multi-stream analysis of security module"
        )
        
    async def practice_codebase_analysis(self):
        """Analyze codebase structure"""
        self.techniques_practiced.add("Codebase Analysis")
        
        # Directory structure analysis
        await self.execute_command(
            "find . -type d -name '__pycache__' -prune -o -type d -print | grep -E '^\\./[^/]+$' | while read dir; do printf '%-20s: %d files\\n' \"$dir\" $(find \"$dir\" -type f | wc -l); done | sort -k2 -nr",
            "Analyze directory sizes by file count"
        )
        
        # Code statistics
        await self.execute_command(
            "{ echo 'Extension,Count,Lines'; find src -type f \\( -name '*.py' -o -name '*.rs' -o -name '*.js' -o -name '*.yaml' \\) | sed 's/.*\\.//' | sort | uniq -c | while read count ext; do lines=$(find src -name \"*.$ext\" -exec cat {} + | wc -l); echo \"$ext,$count,$lines\"; done; } | column -t -s,",
            "Generate code statistics table by file type"
        )
        
    async def practice_performance_analysis(self):
        """Practice performance analysis commands"""
        self.techniques_practiced.add("Performance Analysis")
        
        # Find large functions
        await self.execute_command(
            "for f in $(find src -name '*.py' | head -10); do echo \"=== $f ===\"; awk '/^def |^async def /{name=$0; count=0} {count++} /^def |^async def |^class |^$/{if(count>50 && name) print name \" - \" count \" lines\"; name=\"\"}' \"$f\"; done",
            "Find large functions that might need refactoring"
        )
        
        # Import analysis
        await self.execute_command(
            "find src -name '*.py' -exec head -20 {} \\; | grep -E '^import|^from' | sort | uniq -c | sort -nr | head -15",
            "Most common imports across the codebase"
        )
        
    async def practice_security_scanning(self):
        """Practice security scanning patterns"""
        self.techniques_practiced.add("Security Scanning")
        
        # Find potential SQL injection points
        await self.execute_command(
            "grep -r -n -E 'execute\\(.*%[s|d]|execute\\(.*\\+|execute\\(.*f[\"\\']' src --include='*.py' | grep -v test | head -10",
            "Scan for potential SQL injection vulnerabilities"
        )
        
        # Check for hardcoded values
        await self.execute_command(
            "grep -r -n -E '(api_key|password|secret)\\s*=\\s*[\"\\'][^\"\\']+[\"\\']' src --include='*.py' | grep -v -E '(os\\.getenv|os\\.environ|example|test)' | head -10",
            "Scan for hardcoded secrets"
        )
        
    async def practice_documentation_search(self):
        """Practice documentation searching"""
        self.techniques_practiced.add("Documentation Search")
        
        # Find all markdown documentation
        await self.execute_command(
            "find . -name '*.md' -type f | grep -v node_modules | xargs -I {} sh -c 'echo \"=== {} ===\"; head -3 {}' | grep -B1 -E '^#' | head -20",
            "Survey all documentation files and their titles"
        )
        
        # Extract all TODO items from docs
        await self.execute_command(
            "grep -r -n 'TODO\\|FIXME' . --include='*.md' | cut -d: -f1,3- | sort -u | head -15",
            "Find all TODO items in documentation"
        )
        
    async def practice_git_archaeology(self):
        """Practice git history analysis"""
        self.techniques_practiced.add("Git Archaeology")
        
        # Recent changes analysis
        await self.execute_command(
            "git log --oneline -20 | awk '{print $1}' | xargs -I {} git diff-tree --no-commit-id --name-only -r {} | sort | uniq -c | sort -nr | head -15",
            "Find most frequently modified files in recent commits"
        )
        
        # Author contribution analysis
        await self.execute_command(
            "git log --format='%an' | sort | uniq -c | sort -nr | head -10",
            "Analyze commit contributions by author"
        )
        
    def display_summary(self):
        """Display training session summary"""
        print(f"\n\n{'='*80}")
        print(f"BASHGOD TRAINING SESSION COMPLETE")
        print(f"{'='*80}")
        
        duration = (datetime.now() - self.start_time).total_seconds()
        
        print(f"\n📊 Session Statistics:")
        print(f"   Duration: {duration:.1f} seconds")
        print(f"   Commands Executed: {self.commands_executed}")
        print(f"   Techniques Practiced: {len(self.techniques_practiced)}")
        
        print(f"\n🎯 Techniques Mastered:")
        for technique in sorted(self.techniques_practiced):
            print(f"   ✓ {technique}")
            
        print(f"\n💡 Key Discoveries:")
        # Show top discoveries by output size
        top_discoveries = sorted(self.discoveries, key=lambda x: x['lines_output'], reverse=True)[:5]
        for disc in top_discoveries:
            print(f"   • {disc['description']} ({disc['lines_output']} lines)")
            
        print(f"\n🏆 BASHGOD Status: TRAINING COMPLETE")
        print(f"{'='*80}")
        
        # Save session log
        session_log = {
            'session_id': f"BASHGOD-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'duration_seconds': duration,
            'commands_executed': self.commands_executed,
            'techniques_practiced': list(self.techniques_practiced),
            'discoveries': self.discoveries
        }
        
        log_file = Path('bashgod_session.json')
        with open(log_file, 'w') as f:
            json.dump(session_log, f, indent=2)
            
        print(f"\n📝 Session log saved to: {log_file}")

async def main():
    """Deploy BASHGOD for training"""
    bashgod = BashGod()
    await bashgod.start_training()

if __name__ == "__main__":
    asyncio.run(main())