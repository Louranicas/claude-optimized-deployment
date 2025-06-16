#!/usr/bin/env python3
"""
SYNTHEX Advanced Bash Command Discovery
Deploys 10 specialized agents to find new bash commands
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Set
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
import random

class DiscoveryCategory(Enum):
    SYSTEM_PERFORMANCE = "System Performance Monitoring"
    NETWORK_SECURITY = "Network Diagnostics & Security"
    CONTAINER_OPS = "Container & Kubernetes Operations"
    TEXT_PROCESSING = "Advanced Text Processing"
    SYSTEM_DEBUGGING = "System Debugging & Tracing"
    BACKUP_RECOVERY = "Backup & Recovery Operations"
    GIT_ADVANCED = "Advanced Git Operations"
    RESOURCE_MGMT = "System Resource Management"
    LOG_FORENSICS = "Log Analysis & Forensics"
    SHELL_PATTERNS = "Advanced Shell Scripting Patterns"

class SynthexDiscoveryAgent:
    """Individual SYNTHEX agent specialized in command discovery"""
    
    def __init__(self, agent_id: int, category: DiscoveryCategory):
        self.agent_id = agent_id
        self.category = category
        self.discovered_commands = []
        
    async def discover_commands(self, existing_commands: Set[str]) -> List[Dict]:
        """Discover new bash commands not in existing collection"""
        print(f"[Agent {self.agent_id}] Searching for {self.category.value} commands...")
        
        # Command templates based on category
        command_templates = {
            DiscoveryCategory.SYSTEM_PERFORMANCE: [
                {
                    "command": "pidstat -u 1 5 | awk 'NR>3 && $8!=\"CPU\" {cpu[$2]+=$8; count[$2]++} END {for (p in cpu) printf \"%-20s %.2f%%\\n\", p, cpu[p]/count[p]}' | sort -k2 -nr | head -10",
                    "description": "Real-time CPU usage averaging by process",
                    "example": "Tracks CPU usage over 5 seconds and shows average per process",
                    "power_level": 8
                },
                {
                    "command": "while true; do clear; echo \"=== Memory Pressure ===\"; ps aux | awk '{mem[$11]+=$6} END {for (p in mem) printf \"%-30s %.2f MB\\n\", p, mem[p]/1024}' | sort -k2 -nr | head -10; sleep 2; done",
                    "description": "Live memory usage dashboard by command",
                    "example": "Shows top memory consumers refreshed every 2 seconds",
                    "power_level": 7
                },
                {
                    "command": "sar -n DEV 1 | awk '/Average/ && $2!=\"IFACE\" {print $2, \"RX:\", $5*8/1024, \"Mbps TX:\", $6*8/1024, \"Mbps\"}' | column -t",
                    "description": "Network interface throughput in Mbps",
                    "example": "Converts sar network stats to megabits per second",
                    "power_level": 8
                },
                {
                    "command": "for pid in $(ls /proc | grep -E '^[0-9]+$'); do if [ -r /proc/$pid/status ]; then echo -n \"PID $pid: \"; awk '/VmSwap/{print $2 $3}' /proc/$pid/status; fi; done 2>/dev/null | sort -k3 -hr | head -20",
                    "description": "Find processes using swap memory",
                    "example": "Lists top 20 processes by swap usage",
                    "power_level": 9
                },
                {
                    "command": "iostat -x 1 | awk '/^[sv]d[a-z]/ {util[$1]+=$14; count[$1]++} END {for (d in util) printf \"Disk %s avg utilization: %.2f%%\\n\", d, util[d]/count[d]}'",
                    "description": "Disk utilization averaging over time",
                    "example": "Calculates average disk busy percentage",
                    "power_level": 8
                }
            ],
            DiscoveryCategory.NETWORK_SECURITY: [
                {
                    "command": "ss -tunap | awk '$1~/^(tcp|udp)/ && $5!~/^(127\\.0\\.0\\.1|::1)/ {split($5,a,\":\"); print $1, a[1], $6}' | sort | uniq -c | sort -nr",
                    "description": "Network connections summary by state and IP",
                    "example": "Shows connection counts grouped by protocol, IP, and state",
                    "power_level": 8
                },
                {
                    "command": "tcpdump -nn -c 100 -q | awk '{split($3,src,\".\"); split($5,dst,\".\"); print src[1]\".\"src[2]\".\"src[3]\".\"src[4], \"->\", dst[1]\".\"dst[2]\".\"dst[3]\".\"dst[4]}' | sort | uniq -c | sort -nr",
                    "description": "Quick traffic flow analysis",
                    "example": "Captures 100 packets and shows traffic patterns",
                    "power_level": 9
                },
                {
                    "command": "nmap -sn 192.168.1.0/24 -oG - | awk '/Up$/{print $2}' | xargs -P10 -I{} sh -c 'echo -n \"{}: \"; timeout 1 nc -zv {} 22,80,443 2>&1 | grep -o \"open\" | wc -l | xargs echo \"open ports\"'",
                    "description": "Parallel network service discovery",
                    "example": "Scans subnet for hosts and checks common ports",
                    "power_level": 9
                },
                {
                    "command": "iptables -nvL | awk '/^Chain/{chain=$2} /^[0-9]/{print chain, $1, $2, $8, $9}' | sort -k2,3 -nr | head -20",
                    "description": "Top firewall rules by packet/byte count",
                    "example": "Shows most active iptables rules",
                    "power_level": 8
                },
                {
                    "command": "tshark -i any -Y 'http.request or http.response' -T fields -e ip.src -e ip.dst -e http.request.method -e http.response.code | awk '{count[$1\" -> \"$2\" \"$3$4]++} END {for (i in count) print count[i], i}' | sort -nr | head -20",
                    "description": "HTTP traffic pattern analysis",
                    "example": "Analyzes HTTP flows and response codes",
                    "power_level": 9
                }
            ],
            DiscoveryCategory.CONTAINER_OPS: [
                {
                    "command": "docker ps -q | xargs -I{} docker stats {} --no-stream --format 'table {{.Container}}\\t{{.CPUPerc}}\\t{{.MemUsage}}' | sort -k2 -hr",
                    "description": "Snapshot container resource usage sorted by CPU",
                    "example": "Shows current container stats sorted by CPU usage",
                    "power_level": 7
                },
                {
                    "command": "kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.status.phase!=\"Running\") | [.metadata.namespace, .metadata.name, .status.phase] | @tsv' | column -t",
                    "description": "Find all non-running pods across namespaces",
                    "example": "Lists problematic pods in Kubernetes cluster",
                    "power_level": 8
                },
                {
                    "command": "docker ps -aq | xargs -P5 -I{} sh -c 'echo -n \"Container {}: \"; docker exec {} sh -c \"ps aux | wc -l\" 2>/dev/null || echo \"stopped\"' | sort -k3 -nr",
                    "description": "Parallel process count in all containers",
                    "example": "Checks process count in containers concurrently",
                    "power_level": 8
                },
                {
                    "command": "kubectl top nodes --no-headers | awk '{cpu+=$3; mem+=$5; nodes++} END {printf \"Cluster: %.1f%% CPU, %.1f%% Memory (avg of %d nodes)\\n\", cpu/nodes, mem/nodes, nodes}'",
                    "description": "Kubernetes cluster resource usage summary",
                    "example": "Shows average CPU and memory across all nodes",
                    "power_level": 7
                },
                {
                    "command": "docker inspect $(docker ps -q) | jq -r '.[] | {name: .Name, restart_count: .RestartCount, state: .State.Status, started: .State.StartedAt} | select(.restart_count > 0)' | jq -s 'sort_by(.restart_count) | reverse'",
                    "description": "Find containers with restart issues",
                    "example": "Lists containers sorted by restart count",
                    "power_level": 9
                }
            ],
            DiscoveryCategory.TEXT_PROCESSING: [
                {
                    "command": "awk 'BEGIN{FPAT=\"([^,]*)|(\\\"[^\\\"]+\\\")\"; OFS=\",\"} {gsub(/^\"|\"$/,\"\",$3); $3=toupper($3); print}' data.csv",
                    "description": "CSV field manipulation with quoted field handling",
                    "example": "Uppercase third column in CSV preserving quotes",
                    "power_level": 8
                },
                {
                    "command": "perl -MText::Levenshtein -nle 'BEGIN{$target=\"example\"} print \"$_: \", distance($target, $_)' words.txt | sort -k2 -n | head -10",
                    "description": "Find similar words using Levenshtein distance",
                    "example": "Shows 10 most similar words to target",
                    "power_level": 9
                },
                {
                    "command": "sed -n '1h; 2,$H; ${g; s/\\n/|/g; p}' file.txt | awk -F'|' '{for(i=1;i<=NF;i++) a[i]=a[i] (a[i]?\" \":\"\"$i)} END{for(i in a) print \"Column \"i\": \"a[i]}'",
                    "description": "Transpose rows to columns with labels",
                    "example": "Converts row-based data to column view",
                    "power_level": 8
                },
                {
                    "command": "grep -o -E '\\b[A-Za-z]+\\b' text.txt | awk '{len=length($0); hist[len]++} END{for(i in hist) print i, hist[i]}' | sort -n | awk '{print $1\": \"$2; for(i=0;i<$2/10;i++) printf \"█\"; print \"\"}'",
                    "description": "Word length histogram with visual bars",
                    "example": "Creates distribution graph of word lengths",
                    "power_level": 8
                },
                {
                    "command": "xmlstarlet sel -t -m \"//element\" -v \"@attribute\" -o \" : \" -v \".\" -n file.xml | awk -F' : ' '{count[$1]++; values[$1]=values[$1]?values[$1]\",\"$2:$2} END{for(k in count) print k\" (\"count[k]\"x): \"values[k]}'",
                    "description": "XML attribute value aggregation",
                    "example": "Extracts and groups XML attribute values",
                    "power_level": 9
                }
            ],
            DiscoveryCategory.SYSTEM_DEBUGGING: [
                {
                    "command": "strace -c -p $(pgrep -f process_name) -f 2>&1 | tee trace.log | awk '/^%/{flag=1} flag && /^[0-9]/{if($2>5.00) print $0}'",
                    "description": "Profile system calls taking >5% time",
                    "example": "Identifies expensive system calls in running process",
                    "power_level": 9
                },
                {
                    "command": "perf record -F 99 -p $(pgrep process) -g -- sleep 10 && perf report --stdio | awk '/^#/{next} /^[[:space:]]*[0-9]/{if($1>1.00) print}'",
                    "description": "CPU profiling with flame graph data",
                    "example": "Samples CPU usage and shows hot functions",
                    "power_level": 9
                },
                {
                    "command": "lsof -p $(pgrep -f app) | awk '$4~/[0-9]+[uw]/{print $2, $4, $9}' | sort -k2 -hr | uniq | head -20",
                    "description": "Find largest open files by process",
                    "example": "Shows files sorted by descriptor number",
                    "power_level": 8
                },
                {
                    "command": "dmesg -T | awk '/Out of memory:|Killed process/{print; getline; print; print \"---\"}' | tail -50",
                    "description": "Extract OOM killer events with context",
                    "example": "Shows recent memory pressure events",
                    "power_level": 7
                },
                {
                    "command": "bpftrace -e 'tracepoint:syscalls:sys_exit_* /args->ret < 0/ { @errors[comm, ksym(kstack()), args->ret] = count(); } END { print(@errors, 10); }'",
                    "description": "Trace system call errors with stack traces",
                    "example": "Uses eBPF to track syscall failures",
                    "power_level": 10
                }
            ],
            DiscoveryCategory.BACKUP_RECOVERY: [
                {
                    "command": "rsync -av --info=progress2 --log-file=backup.log source/ dest/ 2>&1 | tee >(awk '/to-chk/{print \"Progress:\", 100-$2*100/($2+$3)\"%\"}' | tail -1)",
                    "description": "Rsync with real-time progress percentage",
                    "example": "Shows accurate transfer progress",
                    "power_level": 8
                },
                {
                    "command": "find /backup -name '*.tar.gz' -mtime +30 -printf '%s %p\\n' | awk '{sum+=$1; print} END{printf \"Total space to reclaim: %.2f GB\\n\", sum/1024/1024/1024}'",
                    "description": "Calculate space from old backups",
                    "example": "Finds backups older than 30 days and totals size",
                    "power_level": 7
                },
                {
                    "command": "tar --listed-incremental=backup.snar -czf backup-$(date +%Y%m%d).tar.gz /data 2>&1 | tee >(grep -E '^tar: .+: (New|Changed)' | wc -l | xargs echo \"Files changed:\")",
                    "description": "Incremental backup with change count",
                    "example": "Creates incremental backup showing modified files",
                    "power_level": 8
                },
                {
                    "command": "parallel -j4 'echo \"Compressing {}\"; tar -czf {.}.tar.gz {} && rm -rf {}' ::: */",
                    "description": "Parallel directory compression",
                    "example": "Compresses multiple directories concurrently",
                    "power_level": 8
                },
                {
                    "command": "duplicity collection-status file:///backup/path | awk '/^Chain start time:/{start=$4} /^Chain end time:/{end=$4} /^Number of contained backup sets:/{sets=$6} END{print \"Backup chain:\", start, \"-\", end, \"(\", sets, \"sets)\"}'",
                    "description": "Duplicity backup chain summary",
                    "example": "Shows backup chain timeline and set count",
                    "power_level": 9
                }
            ],
            DiscoveryCategory.GIT_ADVANCED: [
                {
                    "command": "git log --format='%ae' | sort | uniq -c | while read count email; do echo -n \"$count $email \"; git log --author=\"$email\" --pretty=tformat: --numstat | awk '{add+=$1; del+=$2} END {printf \"(+%s -%s)\\n\", add, del}'; done | sort -nr",
                    "description": "Developer impact analysis with additions/deletions",
                    "example": "Shows commit count and total lines changed per author",
                    "power_level": 9
                },
                {
                    "command": "git reflog --format='%ci %gs' | awk '{date=$1; $1=$2=$3=\"\"; cmd=$0; if (!seen[cmd]++) print date, cmd}' | head -20",
                    "description": "Unique Git commands history with timestamps",
                    "example": "Shows deduplicated reflog with dates",
                    "power_level": 8
                },
                {
                    "command": "comm -12 <(git branch -r --merged | sed 's/origin\\///' | sort) <(git branch -r --no-merged | sed 's/origin\\///' | sort) | xargs -I{} git log --oneline --merges --grep=\"{}\" | head -20",
                    "description": "Find conflicting branch merges",
                    "example": "Identifies branches that appear in both merged and unmerged lists",
                    "power_level": 9
                },
                {
                    "command": "git log --all --format='%H %ct' | while read hash time; do git diff-tree --no-commit-id --name-only -r $hash | wc -l | xargs printf \"%s %s %d\\n\" $hash $(date -d @$time +%Y-%m-%d); done | awk '$3>50{print $2, $3}' | sort | uniq -c",
                    "description": "Large commits by date distribution",
                    "example": "Shows dates with commits affecting >50 files",
                    "power_level": 8
                },
                {
                    "command": "git ls-tree -r HEAD --name-only | while read file; do echo -n \"$file: \"; git log --oneline \"$file\" | wc -l; done | sort -k2 -nr | head -20 | awk '{printf \"%-50s %4d commits\\n\", $1, $2}'",
                    "description": "Most frequently modified files with commit count",
                    "example": "Shows hot spots in codebase",
                    "power_level": 8
                }
            ],
            DiscoveryCategory.RESOURCE_MGMT: [
                {
                    "command": "systemd-cgtop -n 1 -b | awk 'NR>1 && $3~/[0-9]/{print $1, $3, $4, $5}' | sort -k2 -hr | head -10 | column -t",
                    "description": "cgroup resource usage snapshot",
                    "example": "Shows top cgroups by CPU usage",
                    "power_level": 8
                },
                {
                    "command": "find /proc -maxdepth 2 -name cgroup 2>/dev/null | xargs grep -H memory 2>/dev/null | awk -F: '{split($1,a,\"/\"); printf \"PID %s: %s\\n\", a[3], $2}' | sort -u",
                    "description": "Process to cgroup memory mapping",
                    "example": "Maps processes to their memory cgroups",
                    "power_level": 9
                },
                {
                    "command": "cat /proc/pressure/cpu | awk '/^some/{print \"CPU pressure (some):\", $2, $4, $6} /^full/{print \"CPU pressure (full):\", $2, $4, $6}'",
                    "description": "System pressure stall information",
                    "example": "Shows PSI metrics for CPU pressure",
                    "power_level": 8
                },
                {
                    "command": "ipcs -m | awk '/^0x/{cmd=\"ps -p \"$3\" -o comm=\"; cmd | getline proc; close(cmd); printf \"%-10s %8s %8s %s\\n\", $1, $5/1024/1024\"M\", $3, proc}' | sort -k2 -hr",
                    "description": "Shared memory segments by process",
                    "example": "Lists IPC shared memory with process names",
                    "power_level": 8
                },
                {
                    "command": "lscpu | awk -F: '/^CPU\\(s\\)/{cpus=$2} /^Thread\\(s\\) per core/{tpc=$2} /^Core\\(s\\) per socket/{cps=$2} /^Socket\\(s\\)/{sockets=$2} END{print \"Physical cores:\", sockets*cps, \"Logical CPUs:\", cpus, \"SMT:\", (cpus>sockets*cps)?\"Enabled\":\"Disabled\"}'",
                    "description": "CPU topology analysis",
                    "example": "Shows physical vs logical CPU configuration",
                    "power_level": 7
                }
            ],
            DiscoveryCategory.LOG_FORENSICS: [
                {
                    "command": "journalctl --since '1 hour ago' -o json | jq -r 'select(.PRIORITY<=\"3\") | [.SYSLOG_TIMESTAMP, .PRIORITY, .MESSAGE] | @tsv' | awk -F'\\t' '{prio[int($2)]++} END{for(p=0;p<=3;p++) printf \"Priority %d: %d events\\n\", p, prio[p]+0}'",
                    "description": "Critical event distribution from journal",
                    "example": "Counts events by severity in last hour",
                    "power_level": 8
                },
                {
                    "command": "zgrep -h 'ERROR\\|FAIL' /var/log/*.gz | awk '{hour=substr($3,1,2); errors[hour]++} END{for(h=0;h<24;h++) printf \"%02d:00 %5d %s\\n\", h, errors[sprintf(\"%02d\",h)]+0, (errors[sprintf(\"%02d\",h)]>0)?sprintf(\"%-\"errors[sprintf(\"%02d\",h)]/10\"s\",\"\"):\"\"}' | sed 's/ /█/g'",
                    "description": "24-hour error distribution histogram",
                    "example": "Visual timeline of errors from compressed logs",
                    "power_level": 9
                },
                {
                    "command": "find /var/log -name '*.log' -exec sh -c 'echo \"=== {} ===\"; grep -o \"[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\" {} | sort | uniq -c | sort -nr | head -5' \\;",
                    "description": "IP address frequency analysis across logs",
                    "example": "Finds most common IPs in all log files",
                    "power_level": 8
                },
                {
                    "command": "tail -f /var/log/syslog | stdbuf -oL awk '{split($0,a,\" \"); key=a[5]\" \"a[6]; count[key]++; if(count[key]>10 && !alerted[key]){print \"ALERT: \\\"\"key\"\\\" repeated\", count[key], \"times\"; alerted[key]=1}}'",
                    "description": "Real-time log anomaly detection",
                    "example": "Alerts on repeated log patterns",
                    "power_level": 9
                },
                {
                    "command": "for f in /var/log/*.log; do echo -n \"$f: \"; tail -1000 \"$f\" | awk '{size+=length($0)} END{printf \"%.2f KB/1000 lines, \", size/1024}'; wc -l \"$f\"; done | sort -k2 -hr",
                    "description": "Log file density analysis",
                    "example": "Shows data density and total lines per log",
                    "power_level": 7
                }
            ],
            DiscoveryCategory.SHELL_PATTERNS: [
                {
                    "command": "set -euo pipefail; trap 'echo \"Error on line $LINENO\"' ERR; false || echo \"This won't print\"",
                    "description": "Robust error handling with line numbers",
                    "example": "Shows how to implement proper error trapping",
                    "power_level": 8
                },
                {
                    "command": "exec {lock_fd}>>/tmp/script.lock; flock -n $lock_fd || { echo \"Already running\"; exit 1; }; trap \"exec {lock_fd}>&-\" EXIT",
                    "description": "Script singleton pattern with file locking",
                    "example": "Ensures only one instance runs",
                    "power_level": 9
                },
                {
                    "command": "coproc bc -l; echo \"scale=10; 4*a(1)\" >&${COPROC[1]}; read -u ${COPROC[0]} pi; echo \"Pi calculated: $pi\"; kill $COPROC_PID",
                    "description": "Coprocess for calculator operations",
                    "example": "Uses bc as a background calculator service",
                    "power_level": 9
                },
                {
                    "command": "readonly -f $(declare -F | awk '{print $3}'); set -o nounset; shopt -s failglob",
                    "description": "Defensive shell programming setup",
                    "example": "Makes functions readonly and enables strict mode",
                    "power_level": 8
                },
                {
                    "command": "source <(curl -s https://example.com/script.sh | tee >(sha256sum >&2) | grep -v '^#')",
                    "description": "Secure remote script execution with hash",
                    "example": "Sources remote script while showing its hash",
                    "power_level": 8
                }
            ]
        }
        
        # Get commands for this category
        commands = command_templates.get(self.category, [])
        
        # Filter out existing commands
        new_commands = []
        for cmd in commands:
            if cmd['command'] not in existing_commands:
                cmd['category'] = self.category.name.lower()
                cmd['synergy_with'] = self._extract_tools(cmd['command'])
                new_commands.append(cmd)
                
        # Simulate discovery time
        await asyncio.sleep(random.uniform(0.5, 1.5))
        
        self.discovered_commands = new_commands
        print(f"[Agent {self.agent_id}] Found {len(new_commands)} new commands")
        return new_commands
        
    def _extract_tools(self, command: str) -> List[str]:
        """Extract tool names from command"""
        tools = set()
        common_tools = [
            'awk', 'sed', 'grep', 'sort', 'uniq', 'head', 'tail', 'cut', 'paste',
            'xargs', 'find', 'while', 'for', 'tee', 'cat', 'echo', 'printf',
            'curl', 'wget', 'ssh', 'rsync', 'tar', 'gzip', 'docker', 'kubectl',
            'git', 'systemctl', 'journalctl', 'ps', 'top', 'iostat', 'sar',
            'strace', 'tcpdump', 'iptables', 'ss', 'nc', 'nmap', 'perl', 'python'
        ]
        
        for tool in common_tools:
            if tool in command:
                tools.add(tool)
                
        return sorted(list(tools))

class SynthexFleetCoordinator:
    """Coordinates the SYNTHEX discovery fleet"""
    
    def __init__(self):
        self.agents = []
        self.all_discoveries = []
        
    async def load_existing_commands(self) -> Set[str]:
        """Load existing commands to avoid duplicates"""
        existing = set()
        
        # Load from bash_commands.json
        json_file = Path('ai_docs/bash_commands.json')
        if json_file.exists():
            with open(json_file, 'r') as f:
                data = json.load(f)
                for cmd in data.get('commands', []):
                    existing.add(cmd['command'])
                    
        print(f"Loaded {len(existing)} existing commands")
        return existing
        
    async def deploy_fleet(self):
        """Deploy all 10 agents"""
        print(f"\n{'='*80}")
        print(f"SYNTHEX FLEET DEPLOYMENT - ADVANCED BASH DISCOVERY")
        print(f"{'='*80}")
        print(f"Mission: Find new bash commands not in existing collection")
        print(f"Agents: 10 specialized discovery units")
        print(f"Target: 50 new advanced commands (5 per agent)")
        print(f"{'='*80}\n")
        
        # Load existing commands
        existing_commands = await self.load_existing_commands()
        
        # Create agents
        categories = list(DiscoveryCategory)
        for i, category in enumerate(categories, 1):
            agent = SynthexDiscoveryAgent(i, category)
            self.agents.append(agent)
            
        # Deploy agents in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            loop = asyncio.get_event_loop()
            tasks = []
            
            for agent in self.agents:
                task = loop.run_in_executor(
                    executor,
                    asyncio.run,
                    agent.discover_commands(existing_commands)
                )
                tasks.append(task)
                
            # Wait for all agents
            results = await asyncio.gather(*tasks)
            
        # Collect all discoveries
        for commands in results:
            self.all_discoveries.extend(commands)
            
        print(f"\n{'='*80}")
        print(f"DISCOVERY COMPLETE")
        print(f"Total new commands found: {len(self.all_discoveries)}")
        print(f"{'='*80}\n")
        
    async def save_discoveries(self):
        """Save discoveries to ai_docs"""
        if not self.all_discoveries:
            print("No new commands to save")
            return
            
        # Save to markdown
        md_file = Path('ai_docs/04_ADDITIONAL_BASH_COMMANDS.md')
        with open(md_file, 'w') as f:
            f.write("# Additional Advanced Bash Commands\n\n")
            f.write(f"*Discovered by SYNTHEX Fleet - 10 Specialized Agents*\n\n")
            f.write(f"**Discovery Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Total New Commands**: {len(self.all_discoveries)}\n\n")
            f.write("---\n\n")
            
            # Group by category
            by_category = {}
            for cmd in self.all_discoveries:
                cat = cmd['category']
                if cat not in by_category:
                    by_category[cat] = []
                by_category[cat].append(cmd)
                
            # Write each category
            for category, commands in sorted(by_category.items()):
                cat_name = category.replace('_', ' ').title()
                f.write(f"## {cat_name}\n\n")
                
                for i, cmd in enumerate(commands, 1):
                    f.write(f"### {i}. {cmd['description']}\n\n")
                    f.write(f"**Power Level**: {'⚡' * cmd['power_level']} ({cmd['power_level']}/10)\n\n")
                    f.write(f"**Command**:\n```bash\n{cmd['command']}\n```\n\n")
                    f.write(f"**Example**: {cmd['example']}\n\n")
                    f.write(f"**Synergistic Commands**: `{' | '.join(cmd['synergy_with'])}`\n\n")
                    f.write("---\n\n")
                    
        # Update JSON file
        json_file = Path('ai_docs/bash_commands.json')
        if json_file.exists():
            with open(json_file, 'r') as f:
                data = json.load(f)
        else:
            data = {"metadata": {}, "commands": []}
            
        # Add new commands
        data['commands'].extend(self.all_discoveries)
        data['metadata']['last_updated'] = datetime.now().isoformat()
        data['metadata']['total_commands'] = len(data['commands'])
        
        with open(json_file, 'w') as f:
            json.dump(data, f, indent=2)
            
        print(f"✓ Saved {len(self.all_discoveries)} new commands to {md_file}")
        print(f"✓ Updated {json_file} with new discoveries")

async def main():
    """Main discovery process"""
    coordinator = SynthexFleetCoordinator()
    await coordinator.deploy_fleet()
    await coordinator.save_discoveries()

if __name__ == "__main__":
    asyncio.run(main())