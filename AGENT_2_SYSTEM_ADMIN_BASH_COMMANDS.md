# AGENT 2 - SYSTEM ADMINISTRATION BASH COMMANDS
## Comprehensive Command Collection for AMD Ryzen 7 7800X3D with 32GB RAM

### TARGET SYSTEM SPECIFICATIONS
- **CPU**: AMD Ryzen 7 7800X3D (8 cores, 16 threads, Zen 4 architecture)
- **Memory**: 32GB DDR5
- **OS**: Linux Mint (Ubuntu-based)
- **Architecture**: x86_64

---

## 1. CPU & PERFORMANCE MONITORING COMMANDS (25 Commands)

### AMD-Specific CPU Monitoring
```bash
# 1. Install AMD microcode updates
sudo apt install amd64-microcode

# 2. Check CPU temperature (requires lm-sensors)
sensors

# 3. Detect all available sensors
sudo sensors-detect

# 4. Monitor CPU frequency in real-time
watch -n 1 "grep MHz /proc/cpuinfo"

# 5. Check current CPU governor for all cores
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# 6. Set performance governor for all cores
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# 7. Monitor per-core frequency
watch -n 1 "cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq"

# 8. Check available CPU governors
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors

# 9. Monitor CPU temperature with continuous output
watch -n 2 sensors

# 10. Check CPU info including cache details
cat /proc/cpuinfo | grep -E "(processor|model name|cache size|cpu MHz)"

# 11. Monitor CPU usage per core
mpstat -P ALL 1

# 12. Check CPU thermal throttling
dmesg | grep -i thermal

# 13. Monitor CPU power states
sudo powertop --auto-tune

# 14. Check CPU vulnerability status
grep . /sys/devices/system/cpu/vulnerabilities/*

# 15. Monitor CPU load average
uptime

# 16. Real-time CPU monitoring with detailed stats
sar -u 1

# 17. Check CPU cache information
lscpu | grep -i cache

# 18. Monitor context switches
vmstat 1 | awk '{print $12, $13}'

# 19. Check CPU topology
lscpu -e

# 20. Monitor interrupt distribution across cores
watch -n 1 "cat /proc/interrupts | head -20"

# 21. Check CPU utilization by process
ps aux --sort=-%cpu | head -20

# 22. Monitor CPU steal time
iostat -c 1

# 23. Check CPU frequency scaling driver
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_driver

# 24. Monitor real-time CPU usage
top -d 1

# 25. Check CPU idle states
cpupower idle-info
```

### Thread Utilization Tracking
```bash
# 26. Monitor threads per process
ps -eLf | wc -l

# 27. Check thread count for specific process
ps -o thcount -p <PID>

# 28. Monitor thread creation rate
watch -n 1 "ps -eLf | wc -l"

# 29. Check maximum thread limit
cat /proc/sys/kernel/threads-max

# 30. Monitor scheduler statistics
cat /proc/schedstat
```

---

## 2. MEMORY MANAGEMENT COMMANDS (25 Commands)

### 32GB RAM Optimization
```bash
# 31. Check total memory information
free -h

# 32. Display memory usage in MB
free -m

# 33. Continuous memory monitoring
watch -n 1 free -h

# 34. Detailed memory information
cat /proc/meminfo

# 35. Check memory hardware details
sudo dmidecode -t 17

# 36. Monitor swap usage
swapon --show

# 37. Check virtual memory statistics
vmstat 1

# 38. Display memory usage by process
ps aux --sort=-%mem | head -20

# 39. Check memory fragmentation
cat /proc/buddyinfo

# 40. Monitor page allocation failures
dmesg | grep -i "page allocation failure"

# 41. Check memory zones
cat /proc/zoneinfo

# 42. Monitor memory mapped files
cat /proc/meminfo | grep -i mapped

# 43. Check huge pages configuration
cat /proc/meminfo | grep -i huge

# 44. Monitor buffer and cache usage
cat /proc/meminfo | grep -E "(Buffers|Cached)"

# 45. Check dirty pages
cat /proc/meminfo | grep -i dirty

# 46. Monitor slab memory usage
cat /proc/slabinfo | head -20

# 47. Check memory overcommit settings
cat /proc/sys/vm/overcommit_memory

# 48. Monitor memory pressure
cat /proc/pressure/memory

# 49. Check NUMA node memory
numactl --hardware

# 50. Monitor memory bandwidth
sudo perf stat -e cpu/mem-loads/,cpu/mem-stores/ sleep 5

# 51. Check memory type and speed
sudo dmidecode -t memory | grep -E "(Speed|Type)"

# 52. Monitor kernel memory usage
cat /proc/meminfo | grep -i kernel

# 53. Check memory cgroup limits
cat /sys/fs/cgroup/memory/memory.limit_in_bytes

# 54. Monitor anonymous memory
cat /proc/meminfo | grep -i anon

# 55. Check shared memory usage
ipcs -m
```

### Memory Leak Detection
```bash
# 56. Monitor process memory over time
while true; do ps aux | grep <process_name> | awk '{print $6}'; sleep 5; done

# 57. Check memory map for process
cat /proc/<PID>/maps

# 58. Monitor heap usage
cat /proc/<PID>/status | grep -i heap

# 59. Check memory allocation
valgrind --tool=memcheck --leak-check=full <command>

# 60. Monitor RSS memory growth
ps -o pid,rss,comm --sort=-rss | head -20
```

---

## 3. PROCESS MANAGEMENT COMMANDS (25 Commands)

### 16-Thread Process Scheduling
```bash
# 61. Set CPU affinity for process
taskset -c 0-15 <command>

# 62. Check process CPU affinity
taskset -p <PID>

# 63. Set process priority (nice value)
nice -n -10 <command>

# 64. Change running process priority
renice -10 -p <PID>

# 65. Set real-time scheduling policy
chrt -f 50 <command>

# 66. Check process scheduling info
chrt -p <PID>

# 67. Monitor process states
ps aux | awk '{print $8}' | sort | uniq -c

# 68. List processes by CPU usage
ps aux --sort=-%cpu

# 69. List processes by memory usage
ps aux --sort=-%mem

# 70. Monitor process I/O
iotop -p <PID>

# 71. Check process file descriptors
lsof -p <PID>

# 72. Monitor process network connections
netstat -p | grep <PID>

# 73. Check process environment
cat /proc/<PID>/environ | tr '\0' '\n'

# 74. Monitor process tree
pstree -p

# 75. Check process limits
cat /proc/<PID>/limits

# 76. Set process CPU limit
cpulimit -l 50 -p <PID>

# 77. Monitor process context switches
cat /proc/<PID>/status | grep ctxt

# 78. Check process working directory
readlink /proc/<PID>/cwd

# 79. Monitor process system calls
strace -p <PID>

# 80. Check process threads
cat /proc/<PID>/task/*/comm

# 81. Set process I/O priority
ionice -c 1 -n 4 -p <PID>

# 82. Monitor process CPU time
ps -o pid,cputime,comm | grep <process>

# 83. Check process start time
ps -o pid,lstart,comm | grep <process>

# 84. Kill process gracefully
kill -TERM <PID>

# 85. Force kill process
kill -KILL <PID>
```

---

## 4. SYSTEM OPTIMIZATION COMMANDS (25 Commands)

### I/O Performance Tuning
```bash
# 86. Check disk I/O statistics
iostat -x 1

# 87. Monitor disk usage by process
iotop

# 88. Check filesystem mount options
mount | grep -E "ext4|xfs"

# 89. Optimize ext4 mount options
sudo mount -o remount,noatime,barrier=0 /dev/sda1

# 90. Check disk read/write performance
hdparm -tT /dev/sda

# 91. Monitor disk queue depth
cat /sys/block/sda/queue/nr_requests

# 92. Set I/O scheduler
echo deadline | sudo tee /sys/block/sda/queue/scheduler

# 93. Check current I/O scheduler
cat /sys/block/sda/queue/scheduler

# 94. Monitor filesystem cache hit ratio
cat /proc/meminfo | grep -E "Cached|Buffers"

# 95. Flush filesystem caches
sync && echo 3 | sudo tee /proc/sys/vm/drop_caches
```

### Network Stack Optimization
```bash
# 96. Check network interface statistics
cat /proc/net/dev

# 97. Monitor network bandwidth
iftop -i eth0

# 98. Check network buffer sizes
cat /proc/sys/net/core/rmem_max

# 99. Optimize TCP buffer sizes
echo 16777216 | sudo tee /proc/sys/net/core/rmem_max

# 100. Check network interrupt distribution
cat /proc/interrupts | grep eth

# 101. Monitor network connections
ss -tuln

# 102. Check network interface configuration
ethtool eth0

# 103. Set network interface ring buffer
sudo ethtool -G eth0 rx 4096 tx 4096

# 104. Enable TCP offload features
sudo ethtool -K eth0 tso on gso on gro on

# 105. Monitor network latency
ping -c 10 8.8.8.8 | tail -1
```

### Power Management for Ryzen
```bash
# 106. Check current power profile
cat /sys/firmware/acpi/platform_profile

# 107. Set power profile to performance
echo performance | sudo tee /sys/firmware/acpi/platform_profile

# 108. Monitor power consumption
sudo powertop

# 109. Check CPU power states
cpupower idle-info

# 110. Disable CPU power saving
sudo cpupower idle-set -D 0

# 111. Monitor thermal zones
cat /sys/class/thermal/thermal_zone*/temp

# 112. Check cooling devices
cat /sys/class/thermal/cooling_device*/type

# 113. Set CPU frequency manually
sudo cpupower frequency-set -f 4.2GHz

# 114. Check current CPU frequency
cpupower frequency-info

# 115. Monitor package power draw
sudo perf stat -e power/energy-pkg/ sleep 5
```

---

## INTEGRATION WITH MCP SERVER INFRASTRUCTURE

### MCP Integration Commands
```bash
# 116. Start MCP server with resource monitoring
systemctl start mcp-server && systemctl status mcp-server

# 117. Monitor MCP server resource usage
ps aux | grep mcp-server

# 118. Check MCP server log files
journalctl -u mcp-server -f

# 119. Set MCP server CPU affinity
taskset -c 8-15 systemctl restart mcp-server

# 120. Monitor MCP server memory usage
cat /proc/$(pgrep mcp-server)/status | grep VmRSS
```

### Chainable Command Patterns
```bash
# 121. Resource monitoring chain
free -h && vmstat 1 5 && iostat -x 1 3

# 122. Performance baseline capture
(uptime; free -h; ps aux --sort=-%cpu | head -10) > baseline.txt

# 123. System health check chain
sensors && free -h && df -h && systemctl status

# 124. Network and I/O monitoring chain
iftop -t -s 10 & iostat -x 1 10 & wait

# 125. Complete system monitoring pipeline
while true; do echo "$(date): $(uptime | awk '{print $3,$4}') $(free | grep Mem | awk '{print $3/$2 * 100.0}')" >> system_metrics.log; sleep 60; done
```

---

## PRODUCTION DEPLOYMENT INTEGRATION

### Automated Monitoring Scripts
```bash
# 126. Create system health monitoring script
#!/bin/bash
# Monitor critical system resources for Ryzen 7800X3D
CPU_TEMP=$(sensors | grep 'Tctl' | awk '{print $2}' | tr -d '+°C')
MEM_USAGE=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
LOAD_AVG=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',')

echo "$(date): CPU_TEMP=${CPU_TEMP}°C MEM_USAGE=${MEM_USAGE}% LOAD_AVG=${LOAD_AVG}"

# 127. Performance optimization validation
for gov in performance ondemand conservative; do
    echo $gov | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
    sleep 5
    sysbench cpu run --threads=16 --time=10 | grep "events per second"
done

# 128. Memory pressure detection
if [ $(cat /proc/meminfo | grep MemAvailable | awk '{print $2}') -lt 1048576 ]; then
    echo "WARNING: Low memory available"
    ps aux --sort=-%mem | head -10
fi

# 129. Thermal throttling detection
if dmesg | tail -100 | grep -q "thermal"; then
    echo "WARNING: Thermal throttling detected"
    sensors
fi

# 130. System resource trend monitoring
sar -u -r -d 1 3600 > /var/log/performance_$(date +%Y%m%d_%H%M%S).log
```

---

## COMMAND CATEGORIES SUMMARY

### Performance Monitoring Benefits:
- **Real-time system visibility**: Commands 1-30 provide comprehensive CPU monitoring
- **Memory optimization**: Commands 31-60 enable 32GB RAM efficiency tracking
- **Process management**: Commands 61-85 optimize 16-thread utilization
- **System tuning**: Commands 86-115 maximize I/O and network performance

### MCP Server Integration Points:
- Resource monitoring integration (Commands 116-120)
- Automated health checking (Commands 121-125)
- Production deployment monitoring (Commands 126-130)

### Chaining Capabilities:
- Pipeline monitoring workflows
- Automated performance baselines
- Continuous system health validation
- Real-time alerting and logging

This comprehensive collection provides 130+ system administration bash commands specifically optimized for AMD Ryzen 7 7800X3D systems with 32GB RAM, designed for integration with MCP server infrastructure and production deployment pipelines.