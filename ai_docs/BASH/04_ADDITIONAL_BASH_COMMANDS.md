# Additional Advanced Bash Commands

*Discovered by SYNTHEX Fleet - 10 Specialized Agents*

**Discovery Date**: 2025-06-13 18:29:38

**Total New Commands**: 50

---

## Backup Recovery

### 1. Rsync with real-time progress percentage

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
rsync -av --info=progress2 --log-file=backup.log source/ dest/ 2>&1 | tee >(awk '/to-chk/{print "Progress:", 100-$2*100/($2+$3)"%"}' | tail -1)
```

**Example**: Shows accurate transfer progress

**Synergistic Commands**: `awk | nc | rsync | ss | tail | tee`

---

### 2. Calculate space from old backups

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡ (7/10)

**Command**:
```bash
find /backup -name '*.tar.gz' -mtime +30 -printf '%s %p\n' | awk '{sum+=$1; print} END{printf "Total space to reclaim: %.2f GB\n", sum/1024/1024/1024}'
```

**Example**: Finds backups older than 30 days and totals size

**Synergistic Commands**: `awk | find | printf | tar`

---

### 3. Incremental backup with change count

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
tar --listed-incremental=backup.snar -czf backup-$(date +%Y%m%d).tar.gz /data 2>&1 | tee >(grep -E '^tar: .+: (New|Changed)' | wc -l | xargs echo "Files changed:")
```

**Example**: Creates incremental backup showing modified files

**Synergistic Commands**: `echo | grep | nc | tar | tee | xargs`

---

### 4. Parallel directory compression

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
parallel -j4 'echo "Compressing {}"; tar -czf {.}.tar.gz {} && rm -rf {}' ::: */
```

**Example**: Compresses multiple directories concurrently

**Synergistic Commands**: `echo | ss | tar`

---

### 5. Duplicity backup chain summary

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡⚡ (9/10)

**Command**:
```bash
duplicity collection-status file:///backup/path | awk '/^Chain start time:/{start=$4} /^Chain end time:/{end=$4} /^Number of contained backup sets:/{sets=$6} END{print "Backup chain:", start, "-", end, "(", sets, "sets)"}'
```

**Example**: Shows backup chain timeline and set count

**Synergistic Commands**: `awk | tar`

---

## Container Ops

### 1. Snapshot container resource usage sorted by CPU

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡ (7/10)

**Command**:
```bash
docker ps -q | xargs -I{} docker stats {} --no-stream --format 'table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}' | sort -k2 -hr
```

**Example**: Shows current container stats sorted by CPU usage

**Synergistic Commands**: `docker | for | ps | sort | xargs`

---

### 2. Find all non-running pods across namespaces

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.status.phase!="Running") | [.metadata.namespace, .metadata.name, .status.phase] | @tsv' | column -t
```

**Example**: Lists problematic pods in Kubernetes cluster

**Synergistic Commands**: `kubectl`

---

### 3. Parallel process count in all containers

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
docker ps -aq | xargs -P5 -I{} sh -c 'echo -n "Container {}: "; docker exec {} sh -c "ps aux | wc -l" 2>/dev/null || echo "stopped"' | sort -k3 -nr
```

**Example**: Checks process count in containers concurrently

**Synergistic Commands**: `docker | echo | ps | sort | top | xargs`

---

### 4. Kubernetes cluster resource usage summary

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡ (7/10)

**Command**:
```bash
kubectl top nodes --no-headers | awk '{cpu+=$3; mem+=$5; nodes++} END {printf "Cluster: %.1f%% CPU, %.1f%% Memory (avg of %d nodes)\n", cpu/nodes, mem/nodes, nodes}'
```

**Example**: Shows average CPU and memory across all nodes

**Synergistic Commands**: `awk | head | kubectl | printf | top`

---

### 5. Find containers with restart issues

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡⚡ (9/10)

**Command**:
```bash
docker inspect $(docker ps -q) | jq -r '.[] | {name: .Name, restart_count: .RestartCount, state: .State.Status, started: .State.StartedAt} | select(.restart_count > 0)' | jq -s 'sort_by(.restart_count) | reverse'
```

**Example**: Lists containers sorted by restart count

**Synergistic Commands**: `docker | ps | sort | tar`

---

## Git Advanced

### 1. Developer impact analysis with additions/deletions

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡⚡ (9/10)

**Command**:
```bash
git log --format='%ae' | sort | uniq -c | while read count email; do echo -n "$count $email "; git log --author="$email" --pretty=tformat: --numstat | awk '{add+=$1; del+=$2} END {printf "(+%s -%s)\n", add, del}'; done | sort -nr
```

**Example**: Shows commit count and total lines changed per author

**Synergistic Commands**: `awk | echo | for | git | printf | sort | uniq | while`

---

### 2. Unique Git commands history with timestamps

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
git reflog --format='%ci %gs' | awk '{date=$1; $1=$2=$3=""; cmd=$0; if (!seen[cmd]++) print date, cmd}' | head -20
```

**Example**: Shows deduplicated reflog with dates

**Synergistic Commands**: `awk | for | git | head`

---

### 3. Find conflicting branch merges

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡⚡ (9/10)

**Command**:
```bash
comm -12 <(git branch -r --merged | sed 's/origin\///' | sort) <(git branch -r --no-merged | sed 's/origin\///' | sort) | xargs -I{} git log --oneline --merges --grep="{}" | head -20
```

**Example**: Identifies branches that appear in both merged and unmerged lists

**Synergistic Commands**: `git | grep | head | nc | sed | sort | xargs`

---

### 4. Large commits by date distribution

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
git log --all --format='%H %ct' | while read hash time; do git diff-tree --no-commit-id --name-only -r $hash | wc -l | xargs printf "%s %s %d\n" $hash $(date -d @$time +%Y-%m-%d); done | awk '$3>50{print $2, $3}' | sort | uniq -c
```

**Example**: Shows dates with commits affecting >50 files

**Synergistic Commands**: `awk | for | git | printf | sort | uniq | while | xargs`

---

### 5. Most frequently modified files with commit count

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
git ls-tree -r HEAD --name-only | while read file; do echo -n "$file: "; git log --oneline "$file" | wc -l; done | sort -k2 -nr | head -20 | awk '{printf "%-50s %4d commits\n", $1, $2}'
```

**Example**: Shows hot spots in codebase

**Synergistic Commands**: `awk | echo | git | head | printf | sort | while`

---

## Log Forensics

### 1. Critical event distribution from journal

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
journalctl --since '1 hour ago' -o json | jq -r 'select(.PRIORITY<="3") | [.SYSLOG_TIMESTAMP, .PRIORITY, .MESSAGE] | @tsv' | awk -F'\t' '{prio[int($2)]++} END{for(p=0;p<=3;p++) printf "Priority %d: %d events\n", p, prio[p]+0}'
```

**Example**: Counts events by severity in last hour

**Synergistic Commands**: `awk | for | journalctl | nc | printf`

---

### 2. 24-hour error distribution histogram

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡⚡ (9/10)

**Command**:
```bash
zgrep -h 'ERROR\|FAIL' /var/log/*.gz | awk '{hour=substr($3,1,2); errors[hour]++} END{for(h=0;h<24;h++) printf "%02d:00 %5d %s\n", h, errors[sprintf("%02d",h)]+0, (errors[sprintf("%02d",h)]>0)?sprintf("%-"errors[sprintf("%02d",h)]/10"s",""):""}' | sed 's/ /█/g'
```

**Example**: Visual timeline of errors from compressed logs

**Synergistic Commands**: `awk | for | grep | printf | sed`

---

### 3. IP address frequency analysis across logs

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
find /var/log -name '*.log' -exec sh -c 'echo "=== {} ==="; grep -o "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" {} | sort | uniq -c | sort -nr | head -5' \;
```

**Example**: Finds most common IPs in all log files

**Synergistic Commands**: `echo | find | grep | head | sort | uniq`

---

### 4. Real-time log anomaly detection

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡⚡ (9/10)

**Command**:
```bash
tail -f /var/log/syslog | stdbuf -oL awk '{split($0,a," "); key=a[5]" "a[6]; count[key]++; if(count[key]>10 && !alerted[key]){print "ALERT: \""key"\" repeated", count[key], "times"; alerted[key]=1}}'
```

**Example**: Alerts on repeated log patterns

**Synergistic Commands**: `awk | tail`

---

### 5. Log file density analysis

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡ (7/10)

**Command**:
```bash
for f in /var/log/*.log; do echo -n "$f: "; tail -1000 "$f" | awk '{size+=length($0)} END{printf "%.2f KB/1000 lines, ", size/1024}'; wc -l "$f"; done | sort -k2 -hr
```

**Example**: Shows data density and total lines per log

**Synergistic Commands**: `awk | echo | for | printf | sort | tail`

---

## Network Security

### 1. Network connections summary by state and IP

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
ss -tunap | awk '$1~/^(tcp|udp)/ && $5!~/^(127\.0\.0\.1|::1)/ {split($5,a,":"); print $1, a[1], $6}' | sort | uniq -c | sort -nr
```

**Example**: Shows connection counts grouped by protocol, IP, and state

**Synergistic Commands**: `awk | sort | ss | uniq`

---

### 2. Quick traffic flow analysis

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡⚡ (9/10)

**Command**:
```bash
tcpdump -nn -c 100 -q | awk '{split($3,src,"."); split($5,dst,"."); print src[1]"."src[2]"."src[3]"."src[4], "->", dst[1]"."dst[2]"."dst[3]"."dst[4]}' | sort | uniq -c | sort -nr
```

**Example**: Captures 100 packets and shows traffic patterns

**Synergistic Commands**: `awk | sort | tcpdump | uniq`

---

### 3. Parallel network service discovery

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡⚡ (9/10)

**Command**:
```bash
nmap -sn 192.168.1.0/24 -oG - | awk '/Up$/{print $2}' | xargs -P10 -I{} sh -c 'echo -n "{}: "; timeout 1 nc -zv {} 22,80,443 2>&1 | grep -o "open" | wc -l | xargs echo "open ports"'
```

**Example**: Scans subnet for hosts and checks common ports

**Synergistic Commands**: `awk | echo | grep | nc | nmap | xargs`

---

### 4. Top firewall rules by packet/byte count

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
iptables -nvL | awk '/^Chain/{chain=$2} /^[0-9]/{print chain, $1, $2, $8, $9}' | sort -k2,3 -nr | head -20
```

**Example**: Shows most active iptables rules

**Synergistic Commands**: `awk | head | iptables | sort`

---

### 5. HTTP traffic pattern analysis

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡⚡ (9/10)

**Command**:
```bash
tshark -i any -Y 'http.request or http.response' -T fields -e ip.src -e ip.dst -e http.request.method -e http.response.code | awk '{count[$1" -> "$2" "$3$4]++} END {for (i in count) print count[i], i}' | sort -nr | head -20
```

**Example**: Analyzes HTTP flows and response codes

**Synergistic Commands**: `awk | for | head | sort`

---

## Resource Mgmt

### 1. cgroup resource usage snapshot

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
systemd-cgtop -n 1 -b | awk 'NR>1 && $3~/[0-9]/{print $1, $3, $4, $5}' | sort -k2 -hr | head -10 | column -t
```

**Example**: Shows top cgroups by CPU usage

**Synergistic Commands**: `awk | head | sort | top`

---

### 2. Process to cgroup memory mapping

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡⚡ (9/10)

**Command**:
```bash
find /proc -maxdepth 2 -name cgroup 2>/dev/null | xargs grep -H memory 2>/dev/null | awk -F: '{split($1,a,"/"); printf "PID %s: %s\n", a[3], $2}' | sort -u
```

**Example**: Maps processes to their memory cgroups

**Synergistic Commands**: `awk | find | grep | printf | sort | xargs`

---

### 3. System pressure stall information

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
cat /proc/pressure/cpu | awk '/^some/{print "CPU pressure (some):", $2, $4, $6} /^full/{print "CPU pressure (full):", $2, $4, $6}'
```

**Example**: Shows PSI metrics for CPU pressure

**Synergistic Commands**: `awk | cat | ss`

---

### 4. Shared memory segments by process

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
ipcs -m | awk '/^0x/{cmd="ps -p "$3" -o comm="; cmd | getline proc; close(cmd); printf "%-10s %8s %8s %s\n", $1, $5/1024/1024"M", $3, proc}' | sort -k2 -hr
```

**Example**: Lists IPC shared memory with process names

**Synergistic Commands**: `awk | printf | ps | sort`

---

### 5. CPU topology analysis

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡ (7/10)

**Command**:
```bash
lscpu | awk -F: '/^CPU\(s\)/{cpus=$2} /^Thread\(s\) per core/{tpc=$2} /^Core\(s\) per socket/{cps=$2} /^Socket\(s\)/{sockets=$2} END{print "Physical cores:", sockets*cps, "Logical CPUs:", cpus, "SMT:", (cpus>sockets*cps)?"Enabled":"Disabled"}'
```

**Example**: Shows physical vs logical CPU configuration

**Synergistic Commands**: `awk | ps`

---

## Shell Patterns

### 1. Robust error handling with line numbers

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
set -euo pipefail; trap 'echo "Error on line $LINENO"' ERR; false || echo "This won't print"
```

**Example**: Shows how to implement proper error trapping

**Synergistic Commands**: `echo`

---

### 2. Script singleton pattern with file locking

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡⚡ (9/10)

**Command**:
```bash
exec {lock_fd}>>/tmp/script.lock; flock -n $lock_fd || { echo "Already running"; exit 1; }; trap "exec {lock_fd}>&-" EXIT
```

**Example**: Ensures only one instance runs

**Synergistic Commands**: `echo`

---

### 3. Coprocess for calculator operations

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡⚡ (9/10)

**Command**:
```bash
coproc bc -l; echo "scale=10; 4*a(1)" >&${COPROC[1]}; read -u ${COPROC[0]} pi; echo "Pi calculated: $pi"; kill $COPROC_PID
```

**Example**: Uses bc as a background calculator service

**Synergistic Commands**: `echo`

---

### 4. Defensive shell programming setup

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
readonly -f $(declare -F | awk '{print $3}'); set -o nounset; shopt -s failglob
```

**Example**: Makes functions readonly and enables strict mode

**Synergistic Commands**: `awk`

---

### 5. Secure remote script execution with hash

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
source <(curl -s https://example.com/script.sh | tee >(sha256sum >&2) | grep -v '^#')
```

**Example**: Sources remote script while showing its hash

**Synergistic Commands**: `curl | grep | ps | tee`

---

## System Debugging

### 1. Profile system calls taking >5% time

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡⚡ (9/10)

**Command**:
```bash
strace -c -p $(pgrep -f process_name) -f 2>&1 | tee trace.log | awk '/^%/{flag=1} flag && /^[0-9]/{if($2>5.00) print $0}'
```

**Example**: Identifies expensive system calls in running process

**Synergistic Commands**: `awk | grep | ss | strace | tee`

---

### 2. CPU profiling with flame graph data

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡⚡ (9/10)

**Command**:
```bash
perf record -F 99 -p $(pgrep process) -g -- sleep 10 && perf report --stdio | awk '/^#/{next} /^[[:space:]]*[0-9]/{if($1>1.00) print}'
```

**Example**: Samples CPU usage and shows hot functions

**Synergistic Commands**: `awk | grep | ss`

---

### 3. Find largest open files by process

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
lsof -p $(pgrep -f app) | awk '$4~/[0-9]+[uw]/{print $2, $4, $9}' | sort -k2 -hr | uniq | head -20
```

**Example**: Shows files sorted by descriptor number

**Synergistic Commands**: `awk | grep | head | sort | uniq`

---

### 4. Extract OOM killer events with context

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡ (7/10)

**Command**:
```bash
dmesg -T | awk '/Out of memory:|Killed process/{print; getline; print; print "---"}' | tail -50
```

**Example**: Shows recent memory pressure events

**Synergistic Commands**: `awk | ss | tail`

---

### 5. Trace system call errors with stack traces

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡ (10/10)

**Command**:
```bash
bpftrace -e 'tracepoint:syscalls:sys_exit_* /args->ret < 0/ { @errors[comm, ksym(kstack()), args->ret] = count(); } END { print(@errors, 10); }'
```

**Example**: Uses eBPF to track syscall failures

**Synergistic Commands**: ``

---

## System Performance

### 1. Real-time CPU usage averaging by process

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
pidstat -u 1 5 | awk 'NR>3 && $8!="CPU" {cpu[$2]+=$8; count[$2]++} END {for (p in cpu) printf "%-20s %.2f%%\n", p, cpu[p]/count[p]}' | sort -k2 -nr | head -10
```

**Example**: Tracks CPU usage over 5 seconds and shows average per process

**Synergistic Commands**: `awk | for | head | printf | sort`

---

### 2. Live memory usage dashboard by command

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡ (7/10)

**Command**:
```bash
while true; do clear; echo "=== Memory Pressure ==="; ps aux | awk '{mem[$11]+=$6} END {for (p in mem) printf "%-30s %.2f MB\n", p, mem[p]/1024}' | sort -k2 -nr | head -10; sleep 2; done
```

**Example**: Shows top memory consumers refreshed every 2 seconds

**Synergistic Commands**: `awk | echo | for | head | printf | ps | sort | ss | while`

---

### 3. Network interface throughput in Mbps

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
sar -n DEV 1 | awk '/Average/ && $2!="IFACE" {print $2, "RX:", $5*8/1024, "Mbps TX:", $6*8/1024, "Mbps"}' | column -t
```

**Example**: Converts sar network stats to megabits per second

**Synergistic Commands**: `awk | ps | sar`

---

### 4. Find processes using swap memory

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡⚡ (9/10)

**Command**:
```bash
for pid in $(ls /proc | grep -E '^[0-9]+$'); do if [ -r /proc/$pid/status ]; then echo -n "PID $pid: "; awk '/VmSwap/{print $2 $3}' /proc/$pid/status; fi; done 2>/dev/null | sort -k3 -hr | head -20
```

**Example**: Lists top 20 processes by swap usage

**Synergistic Commands**: `awk | echo | for | grep | head | sort`

---

### 5. Disk utilization averaging over time

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
iostat -x 1 | awk '/^[sv]d[a-z]/ {util[$1]+=$14; count[$1]++} END {for (d in util) printf "Disk %s avg utilization: %.2f%%\n", d, util[d]/count[d]}'
```

**Example**: Calculates average disk busy percentage

**Synergistic Commands**: `awk | for | iostat | printf`

---

## Text Processing

### 1. CSV field manipulation with quoted field handling

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
awk 'BEGIN{FPAT="([^,]*)|(\"[^\"]+\")"; OFS=","} {gsub(/^"|"$/,"",$3); $3=toupper($3); print}' data.csv
```

**Example**: Uppercase third column in CSV preserving quotes

**Synergistic Commands**: `awk`

---

### 2. Find similar words using Levenshtein distance

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡⚡ (9/10)

**Command**:
```bash
perl -MText::Levenshtein -nle 'BEGIN{$target="example"} print "$_: ", distance($target, $_)' words.txt | sort -k2 -n | head -10
```

**Example**: Shows 10 most similar words to target

**Synergistic Commands**: `head | nc | perl | sort | tar`

---

### 3. Transpose rows to columns with labels

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
sed -n '1h; 2,$H; ${g; s/\n/|/g; p}' file.txt | awk -F'|' '{for(i=1;i<=NF;i++) a[i]=a[i] (a[i]?" ":""$i)} END{for(i in a) print "Column "i": "a[i]}'
```

**Example**: Converts row-based data to column view

**Synergistic Commands**: `awk | for | sed`

---

### 4. Word length histogram with visual bars

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡ (8/10)

**Command**:
```bash
grep -o -E '\b[A-Za-z]+\b' text.txt | awk '{len=length($0); hist[len]++} END{for(i in hist) print i, hist[i]}' | sort -n | awk '{print $1": "$2; for(i=0;i<$2/10;i++) printf "█"; print ""}'
```

**Example**: Creates distribution graph of word lengths

**Synergistic Commands**: `awk | for | grep | printf | sort`

---

### 5. XML attribute value aggregation

**Power Level**: ⚡⚡⚡⚡⚡⚡⚡⚡⚡ (9/10)

**Command**:
```bash
xmlstarlet sel -t -m "//element" -v "@attribute" -o " : " -v "." -n file.xml | awk -F' : ' '{count[$1]++; values[$1]=values[$1]?values[$1]","$2:$2} END{for(k in count) print k" ("count[k]"x): "values[k]}'
```

**Example**: Extracts and groups XML attribute values

**Synergistic Commands**: `awk | for | tar`

---

