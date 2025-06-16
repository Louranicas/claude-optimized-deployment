#!/usr/bin/env python3
"""
SYNTHEX Parallel Deployment for Advanced Bash Command Research
Deploys 9 SYNTHEX instances to search for advanced bash command chaining techniques
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, List, Any, Set
from pathlib import Path
import re
from dataclasses import dataclass, field
from enum import Enum

class BashCategory(Enum):
    """Categories of advanced bash techniques"""
    PIPE_CHAINS = "pipe_chains"
    PROCESS_SUBSTITUTION = "process_substitution"
    COMMAND_GROUPING = "command_grouping"
    ADVANCED_REDIRECTION = "advanced_redirection"
    CONDITIONAL_EXECUTION = "conditional_execution"
    PARALLEL_EXECUTION = "parallel_execution"
    LOOP_CONSTRUCTS = "loop_constructs"
    STREAM_MANIPULATION = "stream_manipulation"
    PARAMETER_EXPANSION = "parameter_expansion"

@dataclass
class BashCommand:
    """Advanced bash command pattern"""
    command: str
    description: str
    category: BashCategory
    example: str
    synergy_with: List[str] = field(default_factory=list)
    power_level: int = 1  # 1-10 scale

class SynthexBashSearcher:
    """SYNTHEX instance specialized for bash command search"""
    
    def __init__(self, instance_id: int, category: BashCategory):
        self.instance_id = instance_id
        self.category = category
        self.findings: List[BashCommand] = []
        self.name = f"SYNTHEX-{instance_id}-{category.value}"
        
    async def search(self) -> List[BashCommand]:
        """Execute specialized search for bash commands"""
        print(f"[{self.name}] Starting search for {self.category.value}...")
        
        if self.category == BashCategory.PIPE_CHAINS:
            await self._search_pipe_chains()
        elif self.category == BashCategory.PROCESS_SUBSTITUTION:
            await self._search_process_substitution()
        elif self.category == BashCategory.COMMAND_GROUPING:
            await self._search_command_grouping()
        elif self.category == BashCategory.ADVANCED_REDIRECTION:
            await self._search_advanced_redirection()
        elif self.category == BashCategory.CONDITIONAL_EXECUTION:
            await self._search_conditional_execution()
        elif self.category == BashCategory.PARALLEL_EXECUTION:
            await self._search_parallel_execution()
        elif self.category == BashCategory.LOOP_CONSTRUCTS:
            await self._search_loop_constructs()
        elif self.category == BashCategory.STREAM_MANIPULATION:
            await self._search_stream_manipulation()
        elif self.category == BashCategory.PARAMETER_EXPANSION:
            await self._search_parameter_expansion()
            
        print(f"[{self.name}] Found {len(self.findings)} advanced patterns")
        return self.findings
        
    async def _search_pipe_chains(self):
        """Search for advanced pipe chain patterns"""
        self.findings.extend([
            BashCommand(
                command="find . -type f -name '*.log' | xargs grep -l 'ERROR' | while read f; do echo \"=== $f ===\"; grep -C 3 'ERROR' \"$f\"; done | less",
                description="Complex pipe chain for contextual error log analysis",
                category=self.category,
                example="Finds all log files, filters those with ERRORs, shows context",
                synergy_with=["find", "xargs", "grep", "while", "less"],
                power_level=8
            ),
            BashCommand(
                command="ps aux | awk '{sum+=$4} END {print \"Total Memory Usage: \" sum \"%\"}' | tee >(logger -t memory)",
                description="Process memory calculation with simultaneous logging",
                category=self.category,
                example="Calculates total memory usage and logs it",
                synergy_with=["ps", "awk", "tee", "logger"],
                power_level=7
            ),
            BashCommand(
                command="tar -czf - /path/to/dir | tee >(sha256sum > backup.sha256) | ssh user@host 'cat > backup.tar.gz'",
                description="Create compressed backup with checksum while streaming to remote",
                category=self.category,
                example="Backup, checksum, and remote copy in one pipeline",
                synergy_with=["tar", "tee", "sha256sum", "ssh"],
                power_level=9
            ),
            BashCommand(
                command="git log --oneline | head -20 | awk '{print $1}' | xargs -I {} git show {} --stat | grep -E '^[+-]' | awk '{ins+=$1; del+=$2} END {print \"Insertions: \" ins \" Deletions: \" del}'",
                description="Git statistics pipeline for recent commits",
                category=self.category,
                example="Analyzes insertion/deletion stats for last 20 commits",
                synergy_with=["git", "head", "awk", "xargs", "grep"],
                power_level=8
            ),
            BashCommand(
                command="dmesg | tail -f | grep -E '(error|fail|warn)' --line-buffered | while read line; do echo \"[$(date +%Y-%m-%d\\ %H:%M:%S)] $line\" | tee -a kernel_issues.log | mail -s \"Kernel Alert\" admin@example.com; done",
                description="Real-time kernel monitoring with alerts",
                category=self.category,
                example="Monitors kernel messages and sends email alerts",
                synergy_with=["dmesg", "tail", "grep", "while", "tee", "mail"],
                power_level=9
            )
        ])
        
    async def _search_process_substitution(self):
        """Search for process substitution patterns"""
        self.findings.extend([
            BashCommand(
                command="diff <(ls -la /dir1) <(ls -la /dir2)",
                description="Compare directory listings using process substitution",
                category=self.category,
                example="Shows differences between two directory listings",
                synergy_with=["diff", "ls"],
                power_level=6
            ),
            BashCommand(
                command="comm -23 <(sort file1 | uniq) <(sort file2 | uniq)",
                description="Find unique lines in file1 not in file2",
                category=self.category,
                example="Set difference operation on files",
                synergy_with=["comm", "sort", "uniq"],
                power_level=7
            ),
            BashCommand(
                command="paste <(cut -d: -f1 /etc/passwd) <(cut -d: -f7 /etc/passwd) | column -t",
                description="Create formatted table of users and shells",
                category=self.category,
                example="Extracts and formats user/shell information",
                synergy_with=["paste", "cut", "column"],
                power_level=6
            ),
            BashCommand(
                command="while read url; do curl -s \"$url\" | grep -o 'href=\"[^\"]*\"' | sed 's/href=\"\\(.*\\)\"/\\1/g'; done < urls.txt | sort | uniq > all_links.txt",
                description="Extract all links from multiple URLs",
                category=self.category,
                example="Web scraping pipeline for link extraction",
                synergy_with=["while", "curl", "grep", "sed", "sort", "uniq"],
                power_level=8
            ),
            BashCommand(
                command="join -t, <(sort -t, -k1 file1.csv) <(sort -t, -k1 file2.csv) > merged.csv",
                description="SQL-like join operation on CSV files",
                category=self.category,
                example="Merges two CSV files on first column",
                synergy_with=["join", "sort"],
                power_level=7
            )
        ])
        
    async def _search_command_grouping(self):
        """Search for command grouping patterns"""
        self.findings.extend([
            BashCommand(
                command="{ echo \"Starting backup at $(date)\"; rsync -av /source/ /backup/ && echo \"Backup successful\" || echo \"Backup failed\"; echo \"Completed at $(date)\"; } | tee -a backup.log",
                description="Grouped commands for atomic logging operations",
                category=self.category,
                example="Groups multiple commands for unified output handling",
                synergy_with=["echo", "rsync", "date", "tee"],
                power_level=7
            ),
            BashCommand(
                command="(cd /tmp && wget http://example.com/script.sh && chmod +x script.sh && ./script.sh && rm script.sh)",
                description="Subshell for isolated directory operations",
                category=self.category,
                example="Downloads and executes script without changing current directory",
                synergy_with=["cd", "wget", "chmod", "rm"],
                power_level=6
            ),
            BashCommand(
                command="{ find . -name '*.tmp' -print0; find . -name '*.cache' -print0; } | xargs -0 rm -f",
                description="Group multiple find commands for batch deletion",
                category=self.category,
                example="Combines multiple find patterns for efficient cleanup",
                synergy_with=["find", "xargs", "rm"],
                power_level=7
            ),
            BashCommand(
                command="parallel -j 4 'echo \"Processing {}\"; convert {} -resize 800x600 thumb_{}' ::: *.jpg",
                description="Parallel image processing with GNU parallel",
                category=self.category,
                example="Processes multiple images concurrently",
                synergy_with=["parallel", "convert"],
                power_level=9
            ),
            BashCommand(
                command="{ ps aux | head -1; ps aux | grep -v grep | grep httpd; } | awk '{sum+=$6} END {print \"Total RSS: \" sum/1024 \" MB\"}'",
                description="Header-preserving process filtering with calculation",
                category=self.category,
                example="Shows httpd processes with header and total memory",
                synergy_with=["ps", "head", "grep", "awk"],
                power_level=7
            )
        ])
        
    async def _search_advanced_redirection(self):
        """Search for advanced redirection patterns"""
        self.findings.extend([
            BashCommand(
                command="exec 3>&1 4>&2 1>output.log 2>&1; echo \"This goes to log\"; echo \"This goes to screen\" >&3; exec 1>&3 2>&4 3>&- 4>&-",
                description="Advanced file descriptor manipulation for selective output",
                category=self.category,
                example="Redirects stdout/stderr while preserving ability to write to screen",
                synergy_with=["exec", "echo"],
                power_level=9
            ),
            BashCommand(
                command="cat <<< \"$(<file.txt)\" | tr '[:lower:]' '[:upper:]' > file.txt",
                description="In-place file transformation using here-string",
                category=self.category,
                example="Converts file to uppercase in-place",
                synergy_with=["cat", "tr"],
                power_level=6
            ),
            BashCommand(
                command="mkfifo /tmp/fifo; command1 > /tmp/fifo & command2 < /tmp/fifo; rm /tmp/fifo",
                description="Named pipe for inter-process communication",
                category=self.category,
                example="Creates FIFO for complex command communication",
                synergy_with=["mkfifo", "rm"],
                power_level=8
            ),
            BashCommand(
                command="{ echo \"Error occurred\" | tee /dev/stderr | logger -t myapp; } 2>&1 | grep -v '^$'",
                description="Simultaneous stderr, syslog, and stdout with filtering",
                category=self.category,
                example="Multi-destination output with filtering",
                synergy_with=["echo", "tee", "logger", "grep"],
                power_level=8
            ),
            BashCommand(
                command="strace -e trace=file -o >(grep -E 'open|access' | tee file_access.log) command",
                description="Real-time system call filtering and logging",
                category=self.category,
                example="Traces file operations with selective logging",
                synergy_with=["strace", "grep", "tee"],
                power_level=9
            )
        ])
        
    async def _search_conditional_execution(self):
        """Search for conditional execution patterns"""
        self.findings.extend([
            BashCommand(
                command="[ -f ~/.ssh/id_rsa ] || ssh-keygen -t rsa -b 4096 -N '' -f ~/.ssh/id_rsa && ssh-copy-id user@host",
                description="Conditional SSH key generation and deployment",
                category=self.category,
                example="Creates SSH key if missing, then copies to remote",
                synergy_with=["test", "ssh-keygen", "ssh-copy-id"],
                power_level=7
            ),
            BashCommand(
                command="ping -c 1 -W 1 google.com &>/dev/null && echo \"Online\" || echo \"Offline\"",
                description="Network connectivity check with status output",
                category=self.category,
                example="Quick internet connectivity test",
                synergy_with=["ping", "echo"],
                power_level=5
            ),
            BashCommand(
                command="for host in host1 host2 host3; do ssh -o ConnectTimeout=5 $host 'uptime' && echo \"$host: OK\" || echo \"$host: FAILED\"; done | tee status.log",
                description="Multi-host health check with status logging",
                category=self.category,
                example="Checks multiple servers and logs results",
                synergy_with=["for", "ssh", "echo", "tee"],
                power_level=8
            ),
            BashCommand(
                command="until mysql -h localhost -u root -p$PASS -e 'SELECT 1' &>/dev/null; do echo \"Waiting for MySQL...\"; sleep 2; done && echo \"MySQL is ready!\"",
                description="Service readiness check with retry loop",
                category=self.category,
                example="Waits for MySQL to become available",
                synergy_with=["until", "mysql", "echo", "sleep"],
                power_level=7
            ),
            BashCommand(
                command="[[ $(date +%H) -lt 12 ]] && greeting=\"Good morning\" || { [[ $(date +%H) -lt 18 ]] && greeting=\"Good afternoon\" || greeting=\"Good evening\"; }; echo \"$greeting, $USER\"",
                description="Time-based conditional greeting",
                category=self.category,
                example="Dynamic greeting based on time of day",
                synergy_with=["date", "echo"],
                power_level=6
            )
        ])
        
    async def _search_parallel_execution(self):
        """Search for parallel execution patterns"""
        self.findings.extend([
            BashCommand(
                command="for i in {1..10}; do (sleep $((RANDOM % 5)) && echo \"Task $i completed\") & done; wait; echo \"All tasks done\"",
                description="Parallel task execution with synchronization",
                category=self.category,
                example="Runs 10 tasks in parallel and waits for completion",
                synergy_with=["for", "sleep", "wait"],
                power_level=7
            ),
            BashCommand(
                command="cat urls.txt | xargs -P 10 -I {} sh -c 'curl -s {} | wc -l | xargs printf \"%s: %d lines\\n\" {}'",
                description="Parallel URL fetching with line counting",
                category=self.category,
                example="Fetches multiple URLs concurrently and counts lines",
                synergy_with=["cat", "xargs", "curl", "wc"],
                power_level=8
            ),
            BashCommand(
                command="find . -name '*.jpg' -print0 | parallel -0 -j+0 'convert {} -quality 85 compressed_{/}'",
                description="Parallel image compression using all CPU cores",
                category=self.category,
                example="Compresses all JPG files using maximum parallelism",
                synergy_with=["find", "parallel", "convert"],
                power_level=9
            ),
            BashCommand(
                command="seq 1 100 | xargs -n 1 -P 8 -I {} bash -c 'echo \"Processing {}\"; sleep 0.1'",
                description="Controlled parallel execution with progress",
                category=self.category,
                example="Processes 100 items with 8 parallel workers",
                synergy_with=["seq", "xargs", "bash"],
                power_level=6
            ),
            BashCommand(
                command="export -f process_file; find . -type f -name '*.txt' | parallel -j 4 process_file",
                description="Parallel execution of exported shell function",
                category=self.category,
                example="Runs custom function on multiple files in parallel",
                synergy_with=["export", "find", "parallel"],
                power_level=8
            )
        ])
        
    async def _search_loop_constructs(self):
        """Search for advanced loop constructs"""
        self.findings.extend([
            BashCommand(
                command="while IFS=: read -r user pass uid gid desc home shell; do [[ $uid -ge 1000 ]] && echo \"User: $user (UID: $uid) Shell: $shell\"; done < /etc/passwd",
                description="Parse structured data with field splitting",
                category=self.category,
                example="Extracts user information for regular users",
                synergy_with=["while", "read", "echo"],
                power_level=7
            ),
            BashCommand(
                command="for ((i=0, j=100; i<=100; i++, j--)); do printf \"\\rProgress: [%-50s] %d%% (i=%d, j=%d)\" \"$(printf '#%.0s' {1..50} | head -c $((i/2)))\" \"$i\" \"$i\" \"$j\"; sleep 0.1; done; echo",
                description="C-style for loop with progress bar",
                category=self.category,
                example="Shows progress with dual counter",
                synergy_with=["for", "printf", "sleep"],
                power_level=8
            ),
            BashCommand(
                command="mapfile -t files < <(find . -type f -name '*.sh'); for i in \"${!files[@]}\"; do echo \"[$i] ${files[$i]}\"; done",
                description="Array population from command with indexed iteration",
                category=self.category,
                example="Creates indexed list of shell scripts",
                synergy_with=["mapfile", "find", "for"],
                power_level=7
            ),
            BashCommand(
                command="while read -r line; do echo \"$line\" | rev; done < file.txt | tac",
                description="Reverse lines and their content",
                category=self.category,
                example="Completely reverses a text file",
                synergy_with=["while", "read", "rev", "tac"],
                power_level=6
            ),
            BashCommand(
                command="for dir in */; do (cd \"$dir\" && git pull &); done; wait",
                description="Parallel git pull in subdirectories",
                category=self.category,
                example="Updates all git repositories in parallel",
                synergy_with=["for", "cd", "git", "wait"],
                power_level=8
            )
        ])
        
    async def _search_stream_manipulation(self):
        """Search for stream manipulation patterns"""
        self.findings.extend([
            BashCommand(
                command="tail -f /var/log/syslog | stdbuf -oL grep -E '(error|fail)' | while read line; do echo \"$(date): $line\" | tee -a filtered.log; done",
                description="Real-time log filtering with buffering control",
                category=self.category,
                example="Filters and timestamps live log entries",
                synergy_with=["tail", "stdbuf", "grep", "while", "tee"],
                power_level=8
            ),
            BashCommand(
                command="awk 'BEGIN{OFS=\",\"} FNR==1{print $0, \"hash\"} FNR>1{cmd=\"echo \" $0 \" | sha256sum | cut -d\\  -f1\"; cmd | getline hash; close(cmd); print $0, hash}' data.csv",
                description="Add hash column to CSV using AWK",
                category=self.category,
                example="Computes hash for each row in CSV",
                synergy_with=["awk", "sha256sum", "cut"],
                power_level=9
            ),
            BashCommand(
                command="sed -n 'h;n;H;g;s/\\n/ /p' file.txt | awk '{print NR \": \" $0}'",
                description="Merge pairs of lines with line numbers",
                category=self.category,
                example="Combines adjacent lines with numbering",
                synergy_with=["sed", "awk"],
                power_level=7
            ),
            BashCommand(
                command="paste -d' ' <(seq 1 10) <(seq 11 20) | awk '{print $1 * $2}'",
                description="Parallel sequence multiplication",
                category=self.category,
                example="Multiplies corresponding numbers from two sequences",
                synergy_with=["paste", "seq", "awk"],
                power_level=6
            ),
            BashCommand(
                command="tee >(grep ERROR > errors.log) >(grep WARN > warnings.log) < input.log | grep -v -E '(ERROR|WARN)' > info.log",
                description="Multi-stream log splitting",
                category=self.category,
                example="Splits log file into severity-based files",
                synergy_with=["tee", "grep"],
                power_level=8
            )
        ])
        
    async def _search_parameter_expansion(self):
        """Search for parameter expansion patterns"""
        self.findings.extend([
            BashCommand(
                command="for file in *.txt; do mv \"$file\" \"${file%.txt}_$(date +%Y%m%d).${file##*.}\"; done",
                description="Batch rename with date insertion",
                category=self.category,
                example="Adds date to filename before extension",
                synergy_with=["for", "mv", "date"],
                power_level=7
            ),
            BashCommand(
                command="echo ${PATH//:/\\n} | sort | uniq | while read p; do [ -d \"$p\" ] && echo \"✓ $p\" || echo \"✗ $p\"; done",
                description="PATH validation with visual indicators",
                category=self.category,
                example="Checks each PATH directory existence",
                synergy_with=["echo", "sort", "uniq", "while"],
                power_level=6
            ),
            BashCommand(
                command="var='Hello World'; echo \"${var:0:1}${var,,}\" | sed 's/h/H/2'",
                description="Complex string manipulation with expansion",
                category=self.category,
                example="Capitalizes first letter, lowercases rest, then fixes second 'h'",
                synergy_with=["echo", "sed"],
                power_level=5
            ),
            BashCommand(
                command="for i in {1..10}; do printf \"%0${#i}d\\n\" $i; done",
                description="Dynamic width formatting based on value length",
                category=self.category,
                example="Zero-pads numbers based on max width",
                synergy_with=["for", "printf"],
                power_level=6
            ),
            BashCommand(
                command="declare -A count; while read word; do ((count[$word]++)); done < <(tr ' ' '\\n' < text.txt); for word in \"${!count[@]}\"; do echo \"$word: ${count[$word]}\"; done | sort -k2 -nr",
                description="Word frequency counter using associative arrays",
                category=self.category,
                example="Counts word occurrences and sorts by frequency",
                synergy_with=["declare", "while", "tr", "sort"],
                power_level=8
            )
        ])

class SynthexParallelCoordinator:
    """Coordinates multiple SYNTHEX instances for comprehensive bash search"""
    
    def __init__(self):
        self.instances: List[SynthexBashSearcher] = []
        self.all_findings: List[BashCommand] = []
        self.start_time = None
        self.end_time = None
        
    async def deploy_synthex_fleet(self):
        """Deploy 9 SYNTHEX instances in parallel"""
        print(f"\n{'='*80}")
        print("SYNTHEX FLEET DEPLOYMENT - Advanced Bash Command Research")
        print(f"{'='*80}")
        print(f"Deployment Time: {datetime.now().isoformat()}")
        print(f"Mission: Search for advanced bash command chaining and synergy patterns")
        print(f"{'='*80}\n")
        
        # Create 9 SYNTHEX instances, one for each category
        categories = list(BashCategory)
        for i, category in enumerate(categories, 1):
            instance = SynthexBashSearcher(i, category)
            self.instances.append(instance)
            print(f"✓ Deployed {instance.name}")
            
        print(f"\nTotal SYNTHEX instances deployed: {len(self.instances)}")
        
    async def execute_parallel_search(self):
        """Execute search across all instances in parallel"""
        print(f"\n[PHASE 1] Initiating Parallel Search...")
        print("-" * 60)
        
        self.start_time = datetime.now()
        
        # Run all searches in parallel
        search_tasks = [instance.search() for instance in self.instances]
        results = await asyncio.gather(*search_tasks)
        
        # Collect all findings
        for findings in results:
            self.all_findings.extend(findings)
            
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()
        
        print(f"\nSearch completed in {duration:.2f} seconds")
        print(f"Total commands discovered: {len(self.all_findings)}")
        
    def generate_markdown_report(self) -> str:
        """Generate comprehensive markdown report"""
        report = []
        
        # Header
        report.append("# Advanced Bash Command Chaining & Synergy Guide")
        report.append("\n*Generated by SYNTHEX Fleet - 9 Parallel Instances*")
        report.append(f"\n**Generation Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"\n**Total Commands**: {len(self.all_findings)}")
        report.append("\n---\n")
        
        # Table of Contents
        report.append("## Table of Contents\n")
        for i, category in enumerate(BashCategory, 1):
            report.append(f"{i}. [{category.value.replace('_', ' ').title()}](#{category.value})")
        report.append("\n---\n")
        
        # Group findings by category
        by_category = {}
        for finding in self.all_findings:
            if finding.category not in by_category:
                by_category[finding.category] = []
            by_category[finding.category].append(finding)
            
        # Generate sections for each category
        for category in BashCategory:
            if category not in by_category:
                continue
                
            report.append(f"## {category.value.replace('_', ' ').title()}")
            report.append(f"\n### Overview")
            report.append(f"Advanced bash techniques for {category.value.replace('_', ' ')}.\n")
            
            # Sort by power level (descending)
            commands = sorted(by_category[category], key=lambda x: x.power_level, reverse=True)
            
            for i, cmd in enumerate(commands, 1):
                report.append(f"### {i}. {cmd.description}")
                report.append(f"\n**Power Level**: {'⚡' * cmd.power_level} ({cmd.power_level}/10)")
                report.append(f"\n**Command**:")
                report.append(f"```bash")
                report.append(cmd.command)
                report.append(f"```")
                report.append(f"\n**Example**: {cmd.example}")
                
                if cmd.synergy_with:
                    report.append(f"\n**Synergistic Commands**: `{' | '.join(cmd.synergy_with)}`")
                    
                report.append("\n---\n")
                
        # Add power user tips section
        report.append("## Power User Tips\n")
        report.append("### Command Chaining Best Practices\n")
        report.append("1. **Use Process Substitution** for comparing command outputs: `diff <(cmd1) <(cmd2)`")
        report.append("2. **Leverage GNU Parallel** for CPU-bound tasks: `parallel -j+0` uses all cores")
        report.append("3. **Control Buffering** with `stdbuf` for real-time pipeline processing")
        report.append("4. **Group Commands** with `{}` to handle output as a unit")
        report.append("5. **Use Named Pipes** (FIFOs) for complex inter-process communication")
        report.append("6. **Master File Descriptors** for advanced I/O redirection")
        report.append("7. **Combine Tools** for maximum efficiency - each tool should do one thing well")
        
        report.append("\n### Performance Optimization\n")
        report.append("- Prefer `awk` over multiple `grep | sed | cut` chains")
        report.append("- Use `xargs -P` or GNU `parallel` for parallelization")
        report.append("- Minimize subshell creation in loops")
        report.append("- Use parameter expansion instead of external commands when possible")
        report.append("- Buffer output appropriately with `stdbuf` for pipelines")
        
        report.append("\n### Safety Guidelines\n")
        report.append("- Always quote variables: `\"$var\"`")
        report.append("- Use `set -euo pipefail` for robust scripts")
        report.append("- Test complex pipelines incrementally")
        report.append("- Use `-print0` with `find` and `-0` with `xargs` for filename safety")
        report.append("- Implement proper error handling with `trap`")
        
        report.append("\n---\n")
        report.append("*Generated by SYNTHEX - Synthetic Experience Search Engine*")
        
        return "\n".join(report)
        
    async def save_findings(self):
        """Save findings to ai_docs directory"""
        print(f"\n[PHASE 2] Saving Results to ai_docs...")
        print("-" * 60)
        
        # Generate markdown report
        markdown_content = self.generate_markdown_report()
        
        # Save to ai_docs
        ai_docs_path = Path("ai_docs")
        ai_docs_path.mkdir(exist_ok=True)
        
        # Save markdown file
        md_file = ai_docs_path / "03_ADVANCED_BASH_COMMAND_CHAINING.md"
        with open(md_file, 'w') as f:
            f.write(markdown_content)
            
        print(f"✓ Saved markdown guide to: {md_file}")
        
        # Save JSON for programmatic access
        json_data = {
            "metadata": {
                "generated_by": "SYNTHEX Fleet",
                "instances": len(self.instances),
                "timestamp": datetime.now().isoformat(),
                "total_commands": len(self.all_findings)
            },
            "commands": [
                {
                    "command": cmd.command,
                    "description": cmd.description,
                    "category": cmd.category.value,
                    "example": cmd.example,
                    "synergy_with": cmd.synergy_with,
                    "power_level": cmd.power_level
                }
                for cmd in self.all_findings
            ]
        }
        
        json_file = ai_docs_path / "bash_commands.json"
        with open(json_file, 'w') as f:
            json.dump(json_data, f, indent=2)
            
        print(f"✓ Saved JSON data to: {json_file}")
        
        # Update index
        await self.update_documentation_index()
        
    async def update_documentation_index(self):
        """Update the ai_docs index with new entry"""
        index_file = Path("ai_docs/00_AI_DOCS_INDEX.md")
        
        if index_file.exists():
            with open(index_file, 'r') as f:
                content = f.read()
                
            # Add new entry if not already present
            new_entry = "3. [Advanced Bash Command Chaining](./03_ADVANCED_BASH_COMMAND_CHAINING.md) - Comprehensive guide to bash command synergy"
            
            if "03_ADVANCED_BASH_COMMAND_CHAINING.md" not in content:
                # Find the right place to insert (after item 2)
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if line.startswith("2. "):
                        lines.insert(i + 1, new_entry)
                        break
                        
                with open(index_file, 'w') as f:
                    f.write('\n'.join(lines))
                    
                print(f"✓ Updated documentation index")
        
    def print_summary(self):
        """Print execution summary"""
        print(f"\n{'='*80}")
        print("SYNTHEX MISSION COMPLETE")
        print(f"{'='*80}")
        
        # Category breakdown
        category_counts = {}
        for cmd in self.all_findings:
            category_counts[cmd.category.value] = category_counts.get(cmd.category.value, 0) + 1
            
        print("\n📊 Commands by Category:")
        for category, count in category_counts.items():
            print(f"   {category.replace('_', ' ').title()}: {count}")
            
        # Power level distribution
        power_dist = {}
        for cmd in self.all_findings:
            level = f"Level {cmd.power_level}"
            power_dist[level] = power_dist.get(level, 0) + 1
            
        print("\n⚡ Power Level Distribution:")
        for level in range(10, 0, -1):
            key = f"Level {level}"
            if key in power_dist:
                print(f"   {key}: {'█' * power_dist[key]} ({power_dist[key]})")
                
        print(f"\n✅ Total Advanced Bash Commands Documented: {len(self.all_findings)}")
        print(f"📁 Results saved to: ai_docs/03_ADVANCED_BASH_COMMAND_CHAINING.md")
        print(f"{'='*80}")

async def main():
    """Deploy SYNTHEX fleet and execute bash command search"""
    coordinator = SynthexParallelCoordinator()
    
    # Deploy fleet
    await coordinator.deploy_synthex_fleet()
    
    # Execute parallel search
    await coordinator.execute_parallel_search()
    
    # Save findings
    await coordinator.save_findings()
    
    # Print summary
    coordinator.print_summary()

if __name__ == "__main__":
    asyncio.run(main())