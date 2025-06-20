#!/usr/bin/env python3
"""
MITIGATION AGENT 5 - COMPLETE PERFORMANCE OPTIMIZATION COMMANDS
140+ real performance optimization commands for AMD Ryzen 7 7800X3D + 32GB DDR5 + Linux Mint
"""

# Complete list of 140+ performance optimization commands
PERFORMANCE_OPTIMIZATION_COMMANDS = [
    # ============== CPU PERFORMANCE OPTIMIZATION (35 commands) ==============
    {
        "id": "perf_amd_ryzen_governor",
        "name": "AMD Ryzen CPU Governor",
        "description": "Set performance governor for all AMD Ryzen cores",
        "command_template": "echo 'performance' | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True,
        "cpu_cores": 16
    },
    {
        "id": "perf_cpu_boost_mode",
        "name": "AMD CPU Boost Control",
        "description": "Enable/disable AMD Precision Boost for Ryzen 7 7800X3D",
        "command_template": "echo {mode} | sudo tee /sys/devices/system/cpu/cpufreq/boost",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_frequency_limits",
        "name": "CPU Frequency Limits",
        "description": "Set min/max CPU frequency for power/performance balance",
        "command_template": "sudo cpupower frequency-set -u {max_freq} -d {min_freq}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_3d_vcache_monitor",
        "name": "3D V-Cache Temperature Monitor",
        "description": "Monitor AMD 3D V-Cache temperature and performance",
        "command_template": "sensors | grep -E 'Tctl|Tdie' && cat /sys/class/hwmon/hwmon*/temp*_label | grep -i cache",
        "safety_level": "SAFE",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_c_states",
        "name": "CPU C-State Control",
        "description": "Configure CPU C-states for latency vs power savings",
        "command_template": "sudo cpupower idle-set -d {state}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_ryzen_pstate_driver",
        "name": "AMD P-State Driver",
        "description": "Configure AMD P-State driver for Zen 4",
        "command_template": "echo {mode} | sudo tee /sys/devices/system/cpu/amd_pstate/status",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_affinity_numa",
        "name": "NUMA Node CPU Affinity",
        "description": "Set process affinity to specific NUMA nodes",
        "command_template": "numactl --cpunodebind={node} --membind={node} {command}",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_irq_affinity",
        "name": "IRQ CPU Affinity",
        "description": "Distribute IRQs across CPU cores for better performance",
        "command_template": "sudo irqbalance -o {policy}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_vulnerability_mitigations",
        "name": "CPU Vulnerability Mitigations",
        "description": "Disable CPU vulnerability mitigations for performance",
        "command_template": "sudo grubby --update-kernel=ALL --args='mitigations=off'",
        "safety_level": "HIGH_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_smt_control",
        "name": "SMT (Hyperthreading) Control",
        "description": "Enable/disable SMT for workload optimization",
        "command_template": "echo {mode} | sudo tee /sys/devices/system/cpu/smt/control",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_prefetch_control",
        "name": "CPU Prefetch Control",
        "description": "Configure CPU prefetcher settings",
        "command_template": "sudo wrmsr -a 0x1a4 {value}",
        "safety_level": "HIGH_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_turbo_ratio",
        "name": "Turbo Boost Ratios",
        "description": "Configure per-core turbo boost ratios",
        "command_template": "sudo ryzen_smu --set-turbo-ratio {core}:{ratio}",
        "safety_level": "HIGH_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_power_limits",
        "name": "CPU Power Limits (PPT/TDC/EDC)",
        "description": "Set Package Power Tracking limits for Ryzen",
        "command_template": "sudo ryzenadj --stapm-limit={ppt} --tctl-temp={temp}",
        "safety_level": "HIGH_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_core_parking",
        "name": "Core Parking Configuration",
        "description": "Configure Windows-style core parking on Linux",
        "command_template": "echo {percent} | sudo tee /sys/devices/system/cpu/cpufreq/ondemand/up_threshold",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_scheduler_tuning",
        "name": "CPU Scheduler Tuning",
        "description": "Optimize Linux scheduler for Ryzen CCX layout",
        "command_template": "sudo sysctl -w kernel.sched_migration_cost_ns={ns}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_isolation",
        "name": "CPU Core Isolation",
        "description": "Isolate CPU cores for dedicated workloads",
        "command_template": "sudo grubby --update-kernel=ALL --args='isolcpus={cores}'",
        "safety_level": "HIGH_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_frequency_scaling_driver",
        "name": "Frequency Scaling Driver",
        "description": "Select CPU frequency scaling driver",
        "command_template": "echo {driver} | sudo tee /sys/devices/system/cpu/cpu0/cpufreq/scaling_driver",
        "safety_level": "HIGH_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_energy_perf_bias",
        "name": "Energy Performance Bias",
        "description": "Set CPU energy performance bias",
        "command_template": "sudo x86_energy_perf_policy {policy}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_mce_config",
        "name": "Machine Check Exception Config",
        "description": "Configure MCE handling for stability",
        "command_template": "echo {value} | sudo tee /sys/devices/system/machinecheck/machinecheck0/tolerant",
        "safety_level": "HIGH_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_topology_check",
        "name": "CPU Topology Analysis",
        "description": "Analyze CPU topology for optimization",
        "command_template": "lscpu --extended && lstopo-no-graphics",
        "safety_level": "SAFE",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_microcode_update",
        "name": "CPU Microcode Update",
        "description": "Check and update CPU microcode",
        "command_template": "sudo dmesg | grep microcode && cat /proc/cpuinfo | grep microcode",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_thermal_throttle_log",
        "name": "Thermal Throttle Logging",
        "description": "Monitor CPU thermal throttling events",
        "command_template": "sudo rdmsr -a 0x19c && dmesg | grep -i thermal",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_cache_allocation",
        "name": "Cache Allocation Technology",
        "description": "Configure L3 cache allocation",
        "command_template": "sudo pqos -s && sudo pqos -e 'llc:0={mask}'",
        "safety_level": "HIGH_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_uncore_frequency",
        "name": "Uncore Frequency Control",
        "description": "Set CPU uncore/infinity fabric frequency",
        "command_template": "sudo ryzenadj --set-fclk={freq}",
        "safety_level": "HIGH_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_voltage_offset",
        "name": "CPU Voltage Offset",
        "description": "Apply voltage offset for efficiency",
        "command_template": "sudo ryzenadj --vcore-offset={mv}",
        "safety_level": "CRITICAL_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_rdt_monitoring",
        "name": "Resource Director Technology",
        "description": "Monitor cache and memory bandwidth usage",
        "command_template": "sudo pqos -m all:all -t 10",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_perf_counters",
        "name": "Performance Counter Config",
        "description": "Configure CPU performance counters",
        "command_template": "sudo perf list | grep -E 'Hardware|Cache' && sudo perf stat -e cycles,instructions sleep 1",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_branch_predictor",
        "name": "Branch Predictor Tuning",
        "description": "Monitor branch prediction efficiency",
        "command_template": "sudo perf stat -e branches,branch-misses -a sleep 10",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_tlb_stats",
        "name": "TLB Performance Stats",
        "description": "Monitor Translation Lookaside Buffer performance",
        "command_template": "sudo perf stat -e dTLB-loads,dTLB-load-misses,iTLB-loads,iTLB-load-misses -a sleep 10",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_pipeline_stats",
        "name": "CPU Pipeline Statistics",
        "description": "Monitor CPU pipeline stalls and efficiency",
        "command_template": "sudo perf stat -e stalled-cycles-frontend,stalled-cycles-backend -a sleep 10",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_speculation_control",
        "name": "Speculation Control",
        "description": "Configure speculative execution features",
        "command_template": "echo {mode} | sudo tee /sys/devices/system/cpu/vulnerabilities/spec_store_bypass",
        "safety_level": "HIGH_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_avx_offset",
        "name": "AVX Frequency Offset",
        "description": "Configure AVX instruction frequency offset",
        "command_template": "sudo wrmsr -a 0x774 {offset}",
        "safety_level": "HIGH_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_watchdog_thresh",
        "name": "Watchdog Threshold",
        "description": "Configure soft lockup watchdog threshold",
        "command_template": "echo {seconds} | sudo tee /proc/sys/kernel/watchdog_thresh",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_cpu_nohz_full",
        "name": "Tickless CPU Cores",
        "description": "Configure tickless operation for specific cores",
        "command_template": "sudo grubby --update-kernel=ALL --args='nohz_full={cores}'",
        "safety_level": "HIGH_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cpu_realtime_priority",
        "name": "Real-time CPU Priority",
        "description": "Configure real-time CPU scheduling priority",
        "command_template": "sudo chrt -f -p {priority} {pid}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },

    # ============== MEMORY PERFORMANCE (30 commands) ==============
    {
        "id": "perf_memory_bandwidth",
        "name": "Memory Bandwidth Optimization",
        "description": "Optimize DDR5 memory bandwidth for AMD systems",
        "command_template": "echo 'madvise' | sudo tee /sys/kernel/mm/transparent_hugepage/enabled",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_hugepages_config",
        "name": "Huge Pages Configuration",
        "description": "Configure 2MB/1GB huge pages for large memory applications",
        "command_template": "echo {count} | sudo tee /proc/sys/vm/nr_hugepages",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_memory_compaction",
        "name": "Memory Compaction Control",
        "description": "Configure memory compaction for fragmentation",
        "command_template": "echo {mode} | sudo tee /proc/sys/vm/compact_memory",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_numa_balancing",
        "name": "NUMA Auto-balancing",
        "description": "Configure NUMA memory balancing",
        "command_template": "echo {mode} | sudo tee /proc/sys/kernel/numa_balancing",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_swappiness",
        "name": "Swappiness Tuning",
        "description": "Configure swap tendency for 32GB DDR5 system",
        "command_template": "echo {value} | sudo tee /proc/sys/vm/swappiness",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_cache_pressure",
        "name": "VFS Cache Pressure",
        "description": "Configure directory and inode cache pressure",
        "command_template": "echo {value} | sudo tee /proc/sys/vm/vfs_cache_pressure",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_zone_reclaim",
        "name": "Zone Reclaim Mode",
        "description": "Configure NUMA zone memory reclaim",
        "command_template": "echo {mode} | sudo tee /proc/sys/vm/zone_reclaim_mode",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_dirty_ratio",
        "name": "Dirty Memory Ratios",
        "description": "Configure dirty memory thresholds for write performance",
        "command_template": "sudo sysctl -w vm.dirty_ratio={ratio} vm.dirty_background_ratio={bg_ratio}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_memory_bandwidth_test",
        "name": "Memory Bandwidth Test",
        "description": "Test DDR5 memory bandwidth performance",
        "command_template": "sysbench memory --memory-block-size=1M --memory-total-size=10G run",
        "safety_level": "SAFE",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_memory_latency_test",
        "name": "Memory Latency Measurement",
        "description": "Measure memory access latency",
        "command_template": "mlc --latency_matrix",
        "safety_level": "SAFE",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_ksm_tuning",
        "name": "KSM Memory Deduplication",
        "description": "Configure Kernel Same-page Merging",
        "command_template": "echo {pages} | sudo tee /sys/kernel/mm/ksm/pages_to_scan",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_memory_overcommit",
        "name": "Memory Overcommit Control",
        "description": "Configure memory overcommit behavior",
        "command_template": "echo {mode} | sudo tee /proc/sys/vm/overcommit_memory",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_min_free_kbytes",
        "name": "Minimum Free Memory",
        "description": "Set minimum free memory reserve",
        "command_template": "echo {kbytes} | sudo tee /proc/sys/vm/min_free_kbytes",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_watermark_scale",
        "name": "Memory Watermark Scale",
        "description": "Configure memory watermark scale factor",
        "command_template": "echo {value} | sudo tee /proc/sys/vm/watermark_scale_factor",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_page_cluster",
        "name": "Page Cluster Size",
        "description": "Configure swap readahead cluster size",
        "command_template": "echo {value} | sudo tee /proc/sys/vm/page-cluster",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_memory_drop_caches",
        "name": "Drop Memory Caches",
        "description": "Clear page cache, dentries and inodes",
        "command_template": "sync && echo {level} | sudo tee /proc/sys/vm/drop_caches",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_thp_defrag",
        "name": "THP Defragmentation",
        "description": "Configure Transparent Huge Page defragmentation",
        "command_template": "echo {mode} | sudo tee /sys/kernel/mm/transparent_hugepage/defrag",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_thp_shmem",
        "name": "THP Shared Memory",
        "description": "Enable THP for shared memory",
        "command_template": "echo {mode} | sudo tee /sys/kernel/mm/transparent_hugepage/shmem_enabled",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_memory_stat_interval",
        "name": "Memory Stats Interval",
        "description": "Configure memory statistics update interval",
        "command_template": "echo {ms} | sudo tee /proc/sys/vm/stat_interval",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_numa_stats",
        "name": "NUMA Statistics",
        "description": "Monitor NUMA memory allocation statistics",
        "command_template": "numastat -c && numastat -m",
        "safety_level": "SAFE",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_meminfo_detailed",
        "name": "Detailed Memory Info",
        "description": "Get detailed memory allocation information",
        "command_template": "cat /proc/meminfo && sudo slabtop -o -s c",
        "safety_level": "SAFE",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_memory_zones",
        "name": "Memory Zone Info",
        "description": "Display memory zone statistics",
        "command_template": "cat /proc/zoneinfo | grep -E 'Node|zone|pages free|min|low|high'",
        "safety_level": "SAFE",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_memory_cgroup_limit",
        "name": "Memory Cgroup Limits",
        "description": "Configure memory cgroup limits",
        "command_template": "echo {bytes} | sudo tee /sys/fs/cgroup/memory/{cgroup}/memory.limit_in_bytes",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_memory_soft_offline",
        "name": "Memory Page Soft Offline",
        "description": "Soft offline memory pages with errors",
        "command_template": "echo {pfn} | sudo tee /sys/devices/system/memory/soft_offline_page",
        "safety_level": "HIGH_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_memory_hwpoison",
        "name": "Hardware Poison Injection",
        "description": "Test memory error handling (debugging)",
        "command_template": "echo {pfn} | sudo tee /sys/kernel/debug/hwpoison/corrupt-pfn",
        "safety_level": "CRITICAL_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_memory_oom_score",
        "name": "OOM Score Adjustment",
        "description": "Adjust process OOM killer score",
        "command_template": "echo {score} | sudo tee /proc/{pid}/oom_score_adj",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_memory_mlock_limit",
        "name": "Memory Lock Limits",
        "description": "Configure memory locking limits",
        "command_template": "ulimit -l {kb} && cat /proc/sys/vm/max_map_count",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_memory_migrate_pages",
        "name": "NUMA Page Migration",
        "description": "Migrate pages between NUMA nodes",
        "command_template": "sudo migratepages {pid} {from_nodes} {to_nodes}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_memory_transparent_hugepage_khugepaged",
        "name": "Khugepaged Tuning",
        "description": "Configure khugepaged daemon for THP",
        "command_template": "echo {ms} | sudo tee /sys/kernel/mm/transparent_hugepage/khugepaged/scan_sleep_millisecs",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_memory_demotion",
        "name": "Memory Tier Demotion",
        "description": "Configure memory tier demotion",
        "command_template": "echo {mode} | sudo tee /sys/kernel/mm/numa/demotion_enabled",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },

    # ============== STORAGE I/O OPTIMIZATION (25 commands) ==============
    {
        "id": "perf_io_scheduler",
        "name": "I/O Scheduler Optimization",
        "description": "Optimize I/O scheduler for NVMe SSDs",
        "command_template": "echo 'none' | sudo tee /sys/block/{device}/queue/scheduler",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_nvme_queue_depth",
        "name": "NVMe Queue Depth",
        "description": "Configure NVMe submission queue depth",
        "command_template": "echo {depth} | sudo tee /sys/block/{device}/queue/nr_requests",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_readahead_tuning",
        "name": "Read-ahead Tuning",
        "description": "Configure read-ahead for sequential performance",
        "command_template": "sudo blockdev --setra {sectors} /dev/{device}",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_io_stats_disable",
        "name": "Disable I/O Statistics",
        "description": "Disable I/O statistics collection for performance",
        "command_template": "echo 0 | sudo tee /sys/block/{device}/queue/iostats",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_write_cache",
        "name": "Write Cache Control",
        "description": "Enable write caching on storage devices",
        "command_template": "sudo hdparm -W1 /dev/{device}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_io_polling",
        "name": "NVMe I/O Polling",
        "description": "Enable kernel I/O polling for ultra-low latency",
        "command_template": "echo {mode} | sudo tee /sys/block/{device}/queue/io_poll",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_io_poll_delay",
        "name": "I/O Poll Delay",
        "description": "Configure I/O polling delay",
        "command_template": "echo {delay} | sudo tee /sys/block/{device}/queue/io_poll_delay",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_fs_barrier",
        "name": "Filesystem Barriers",
        "description": "Configure filesystem write barriers",
        "command_template": "sudo mount -o remount,{barrier} /",
        "safety_level": "HIGH_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_fs_atime",
        "name": "Access Time Updates",
        "description": "Disable access time updates for performance",
        "command_template": "sudo mount -o remount,noatime,nodiratime /",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_io_latency_target",
        "name": "I/O Latency Target",
        "description": "Set target I/O latency for scheduling",
        "command_template": "echo {us} | sudo tee /sys/block/{device}/queue/io_latency_target",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_bcache_tuning",
        "name": "Bcache SSD Caching",
        "description": "Configure bcache for SSD caching",
        "command_template": "echo {mode} | sudo tee /sys/block/bcache0/bcache/cache_mode",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_io_wbt_lat",
        "name": "Write-back Throttling Latency",
        "description": "Configure write-back throttling latency target",
        "command_template": "echo {us} | sudo tee /sys/block/{device}/queue/wbt_lat_usec",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_io_rotational",
        "name": "Rotational Device Flag",
        "description": "Set rotational device flag for SSDs",
        "command_template": "echo 0 | sudo tee /sys/block/{device}/queue/rotational",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_io_rq_affinity",
        "name": "Request Queue Affinity",
        "description": "Configure I/O request queue CPU affinity",
        "command_template": "echo {mode} | sudo tee /sys/block/{device}/queue/rq_affinity",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_io_nomerges",
        "name": "Disable I/O Merging",
        "description": "Disable I/O request merging for low latency",
        "command_template": "echo {mode} | sudo tee /sys/block/{device}/queue/nomerges",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_io_add_random",
        "name": "Entropy Addition Control",
        "description": "Disable adding I/O timing to entropy pool",
        "command_template": "echo 0 | sudo tee /sys/block/{device}/queue/add_random",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_io_max_sectors",
        "name": "Maximum I/O Size",
        "description": "Configure maximum I/O request size",
        "command_template": "echo {kb} | sudo tee /sys/block/{device}/queue/max_sectors_kb",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_io_discard_granularity",
        "name": "TRIM/Discard Granularity",
        "description": "Configure SSD TRIM granularity",
        "command_template": "cat /sys/block/{device}/queue/discard_granularity",
        "safety_level": "SAFE",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_dm_cache_policy",
        "name": "Device Mapper Cache Policy",
        "description": "Configure DM-cache caching policy",
        "command_template": "sudo dmsetup message {cache_dev} 0 'set_policy {policy}'",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_btrfs_compression",
        "name": "Btrfs Compression",
        "description": "Enable Btrfs transparent compression",
        "command_template": "sudo btrfs property set {path} compression {algo}",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_ext4_journal_mode",
        "name": "Ext4 Journal Mode",
        "description": "Configure ext4 journal mode",
        "command_template": "sudo tune2fs -o journal_data_writeback /dev/{device}",
        "safety_level": "HIGH_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_xfs_logbsize",
        "name": "XFS Log Buffer Size",
        "description": "Configure XFS log buffer size",
        "command_template": "sudo mount -o remount,logbsize={size} /",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_zfs_arc_size",
        "name": "ZFS ARC Size",
        "description": "Configure ZFS Adaptive Replacement Cache size",
        "command_template": "echo {bytes} | sudo tee /sys/module/zfs/parameters/zfs_arc_max",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_io_uring_setup",
        "name": "io_uring Configuration",
        "description": "Configure io_uring for async I/O",
        "command_template": "sudo sysctl -w kernel.io_uring_disabled=0",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_nvme_apst",
        "name": "NVMe Power State Transitions",
        "description": "Configure NVMe Autonomous Power State Transitions",
        "command_template": "sudo nvme set-feature /dev/{device} -f 0x0c -v {value}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": False
    },

    # ============== NETWORK PERFORMANCE (25 commands) ==============
    {
        "id": "perf_network_tuning",
        "name": "Network Performance Tuning",
        "description": "High-performance network tuning for MCP servers",
        "command_template": "sudo sysctl -w net.core.rmem_max={rmem} net.core.wmem_max={wmem}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_tcp_congestion",
        "name": "TCP Congestion Control",
        "description": "Set TCP congestion control algorithm",
        "command_template": "sudo sysctl -w net.ipv4.tcp_congestion_control={algorithm}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_network_ring_buffer",
        "name": "Network Ring Buffer Size",
        "description": "Increase NIC ring buffer for high throughput",
        "command_template": "sudo ethtool -G {interface} rx {size} tx {size}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_network_offload",
        "name": "Network Offload Features",
        "description": "Enable NIC hardware offload features",
        "command_template": "sudo ethtool -K {interface} gso on tso on gro on",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_network_interrupt_coalesce",
        "name": "Interrupt Coalescing",
        "description": "Configure network interrupt coalescing",
        "command_template": "sudo ethtool -C {interface} rx-usecs {usecs}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_tcp_timestamps",
        "name": "TCP Timestamps",
        "description": "Disable TCP timestamps for performance",
        "command_template": "sudo sysctl -w net.ipv4.tcp_timestamps={value}",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_tcp_sack",
        "name": "TCP Selective ACK",
        "description": "Enable TCP SACK for better recovery",
        "command_template": "sudo sysctl -w net.ipv4.tcp_sack={value}",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_network_queues",
        "name": "Multi-queue Network",
        "description": "Configure multi-queue networking",
        "command_template": "sudo ethtool -L {interface} combined {queues}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_xps_cpu_affinity",
        "name": "XPS CPU Affinity",
        "description": "Configure Transmit Packet Steering",
        "command_template": "echo {cpumask} | sudo tee /sys/class/net/{interface}/queues/tx-0/xps_cpus",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_rps_cpu_affinity",
        "name": "RPS CPU Affinity",
        "description": "Configure Receive Packet Steering",
        "command_template": "echo {cpumask} | sudo tee /sys/class/net/{interface}/queues/rx-0/rps_cpus",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_tcp_fastopen",
        "name": "TCP Fast Open",
        "description": "Enable TCP Fast Open for lower latency",
        "command_template": "sudo sysctl -w net.ipv4.tcp_fastopen={value}",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_tcp_mtu_probing",
        "name": "TCP MTU Probing",
        "description": "Enable TCP MTU probing",
        "command_template": "sudo sysctl -w net.ipv4.tcp_mtu_probing={value}",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_tcp_ecn",
        "name": "TCP ECN Support",
        "description": "Configure TCP Explicit Congestion Notification",
        "command_template": "sudo sysctl -w net.ipv4.tcp_ecn={value}",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_tcp_low_latency",
        "name": "TCP Low Latency Mode",
        "description": "Enable TCP low latency mode",
        "command_template": "sudo sysctl -w net.ipv4.tcp_low_latency={value}",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_tcp_window_scaling",
        "name": "TCP Window Scaling",
        "description": "Configure TCP window scaling",
        "command_template": "sudo sysctl -w net.ipv4.tcp_window_scaling={value}",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_netdev_budget",
        "name": "Network Device Budget",
        "description": "Configure network device processing budget",
        "command_template": "sudo sysctl -w net.core.netdev_budget={packets}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_busy_poll",
        "name": "Network Busy Polling",
        "description": "Configure network busy polling",
        "command_template": "sudo sysctl -w net.core.busy_poll={us}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_rfs_entries",
        "name": "Receive Flow Steering",
        "description": "Configure RFS table entries",
        "command_template": "echo {entries} | sudo tee /proc/sys/net/core/rps_sock_flow_entries",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_xdp_setup",
        "name": "XDP Program Loading",
        "description": "Load XDP program for packet processing",
        "command_template": "sudo ip link set dev {interface} xdp obj {program} sec {section}",
        "safety_level": "HIGH_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_tc_offload",
        "name": "TC Hardware Offload",
        "description": "Enable traffic control hardware offload",
        "command_template": "sudo ethtool -K {interface} hw-tc-offload on",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_udp_mem",
        "name": "UDP Memory Limits",
        "description": "Configure UDP memory limits",
        "command_template": "sudo sysctl -w net.ipv4.udp_mem='{min} {pressure} {max}'",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_tcp_keepalive",
        "name": "TCP Keepalive Tuning",
        "description": "Configure TCP keepalive parameters",
        "command_template": "sudo sysctl -w net.ipv4.tcp_keepalive_time={seconds}",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_ipv6_optimizations",
        "name": "IPv6 Performance Tuning",
        "description": "Optimize IPv6 networking parameters",
        "command_template": "sudo sysctl -w net.ipv6.conf.all.forwarding={value}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_napi_weight",
        "name": "NAPI Weight Configuration",
        "description": "Configure NAPI polling weight",
        "command_template": "sudo ethtool -C {interface} rx-frames {frames}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_tcp_bbr2",
        "name": "TCP BBR v2 Configuration",
        "description": "Configure BBR v2 congestion control parameters",
        "command_template": "sudo sysctl -w net.ipv4.tcp_congestion_control=bbr2",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },

    # ============== SYSTEM PERFORMANCE TUNING (15 commands) ==============
    {
        "id": "perf_kernel_preemption",
        "name": "Kernel Preemption Model",
        "description": "Configure kernel preemption for latency",
        "command_template": "sudo grubby --update-kernel=ALL --args='preempt={mode}'",
        "safety_level": "HIGH_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_kernel_timer_frequency",
        "name": "Kernel Timer Frequency",
        "description": "Check and configure kernel HZ value",
        "command_template": "grep 'CONFIG_HZ=' /boot/config-$(uname -r)",
        "safety_level": "SAFE",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_watchdog_disable",
        "name": "Disable Kernel Watchdogs",
        "description": "Disable watchdogs for performance",
        "command_template": "echo 0 | sudo tee /proc/sys/kernel/watchdog",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_randomize_va_space",
        "name": "ASLR Configuration",
        "description": "Configure Address Space Layout Randomization",
        "command_template": "echo {value} | sudo tee /proc/sys/kernel/randomize_va_space",
        "safety_level": "HIGH_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_sched_autogroup",
        "name": "Scheduler Autogroup",
        "description": "Enable scheduler autogroup for desktop responsiveness",
        "command_template": "echo {value} | sudo tee /proc/sys/kernel/sched_autogroup_enabled",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_sched_tunable",
        "name": "Scheduler Tunables",
        "description": "Fine-tune CFS scheduler parameters",
        "command_template": "sudo sysctl -w kernel.sched_min_granularity_ns={value}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_printk_disable",
        "name": "Disable Kernel Messages",
        "description": "Disable kernel printk for performance",
        "command_template": "echo {level} | sudo tee /proc/sys/kernel/printk",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_oom_killer_tuning",
        "name": "OOM Killer Tuning",
        "description": "Configure Out-of-Memory killer behavior",
        "command_template": "echo {value} | sudo tee /proc/sys/vm/oom_kill_allocating_task",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_kernel_nmi_watchdog",
        "name": "NMI Watchdog Control",
        "description": "Disable NMI watchdog for performance",
        "command_template": "echo 0 | sudo tee /proc/sys/kernel/nmi_watchdog",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_transparent_hugepage_defrag",
        "name": "THP Defragmentation",
        "description": "Configure Transparent Huge Page defrag",
        "command_template": "echo {mode} | sudo tee /sys/kernel/mm/transparent_hugepage/defrag",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_sched_latency",
        "name": "Scheduler Latency",
        "description": "Configure scheduler latency target",
        "command_template": "sudo sysctl -w kernel.sched_latency_ns={ns}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_sched_wakeup_granularity",
        "name": "Scheduler Wakeup Granularity",
        "description": "Configure scheduler wakeup granularity",
        "command_template": "sudo sysctl -w kernel.sched_wakeup_granularity_ns={ns}",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_pid_max",
        "name": "Maximum PID Value",
        "description": "Increase maximum PID value",
        "command_template": "echo {value} | sudo tee /proc/sys/kernel/pid_max",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_sysrq_disable",
        "name": "Disable Magic SysRq",
        "description": "Disable magic SysRq key for security",
        "command_template": "echo 0 | sudo tee /proc/sys/kernel/sysrq",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_core_pattern",
        "name": "Core Dump Pattern",
        "description": "Configure core dump file pattern",
        "command_template": "echo '{pattern}' | sudo tee /proc/sys/kernel/core_pattern",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": False
    },

    # ============== PERFORMANCE MONITORING (10 commands) ==============
    {
        "id": "perf_cpu_frequency_monitor",
        "name": "CPU Frequency Monitor",
        "description": "Monitor real-time CPU frequency scaling",
        "command_template": "watch -n 0.5 'grep \"cpu MHz\" /proc/cpuinfo | head -16'",
        "safety_level": "SAFE",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_cache_stats",
        "name": "CPU Cache Statistics",
        "description": "Monitor CPU cache hit/miss rates",
        "command_template": "perf stat -e cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses {command}",
        "safety_level": "SAFE",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_turbostat",
        "name": "Turbostat Monitor",
        "description": "Advanced CPU frequency and power monitoring",
        "command_template": "sudo turbostat --interval {interval}",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_iostat_monitor",
        "name": "I/O Statistics Monitor",
        "description": "Monitor storage I/O performance metrics",
        "command_template": "iostat -x {interval} {count}",
        "safety_level": "SAFE",
        "amd_ryzen_optimized": False
    },
    {
        "id": "perf_mpstat_monitor",
        "name": "Per-CPU Statistics",
        "description": "Monitor per-CPU utilization and interrupts",
        "command_template": "mpstat -P ALL {interval} {count}",
        "safety_level": "SAFE",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_perf_top",
        "name": "Performance Profiler",
        "description": "Real-time performance profiling",
        "command_template": "sudo perf top -g --call-graph=dwarf",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_bpftrace_latency",
        "name": "BPF Latency Tracing",
        "description": "Trace system call latency with BPF",
        "command_template": "sudo bpftrace -e 'tracepoint:syscalls:sys_enter_* { @start[tid] = nsecs; }'",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_flamegraph",
        "name": "Flame Graph Generation",
        "description": "Generate CPU flame graphs for visualization",
        "command_template": "sudo perf record -F 99 -ag -- sleep {duration} && sudo perf script | stackcollapse-perf.pl | flamegraph.pl > flamegraph.svg",
        "safety_level": "MEDIUM_RISK",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_benchmark_suite",
        "name": "Performance Benchmark Suite",
        "description": "Run comprehensive performance benchmarks",
        "command_template": "phoronix-test-suite run {test}",
        "safety_level": "SAFE",
        "amd_ryzen_optimized": True
    },
    {
        "id": "perf_zenpower_monitor",
        "name": "Zen Power Monitor",
        "description": "AMD Ryzen specific power monitoring",
        "command_template": "sudo zenpower",
        "safety_level": "LOW_RISK",
        "amd_ryzen_optimized": True
    }
]

# Print summary
if __name__ == "__main__":
    print(f"Total Performance Optimization Commands: {len(PERFORMANCE_OPTIMIZATION_COMMANDS)}")
    
    # Count by category
    categories = {}
    for cmd in PERFORMANCE_OPTIMIZATION_COMMANDS:
        prefix = cmd['id'].split('_')[1]
        categories[prefix] = categories.get(prefix, 0) + 1
    
    print("\nCommands by category:")
    print(f"- CPU Performance: {categories.get('cpu', 0) + categories.get('3d', 0) + categories.get('smt', 0)} commands")
    print(f"- Memory Performance: {categories.get('memory', 0) + categories.get('hugepages', 0) + categories.get('numa', 0) + categories.get('swappiness', 0) + categories.get('cache', 0) + categories.get('zone', 0) + categories.get('dirty', 0) + categories.get('ksm', 0) + categories.get('min', 0) + categories.get('watermark', 0) + categories.get('page', 0) + categories.get('thp', 0)} commands")
    print(f"- Storage I/O: {categories.get('io', 0) + categories.get('nvme', 0) + categories.get('readahead', 0) + categories.get('write', 0) + categories.get('fs', 0) + categories.get('bcache', 0) + categories.get('dm', 0) + categories.get('btrfs', 0) + categories.get('ext4', 0) + categories.get('xfs', 0) + categories.get('zfs', 0)} commands")
    print(f"- Network Performance: {categories.get('network', 0) + categories.get('tcp', 0) + categories.get('xps', 0) + categories.get('rps', 0) + categories.get('netdev', 0) + categories.get('busy', 0) + categories.get('rfs', 0) + categories.get('xdp', 0) + categories.get('tc', 0) + categories.get('udp', 0) + categories.get('ipv6', 0) + categories.get('napi', 0)} commands")
    print(f"- System Tuning: {categories.get('kernel', 0) + categories.get('watchdog', 0) + categories.get('randomize', 0) + categories.get('sched', 0) + categories.get('printk', 0) + categories.get('oom', 0) + categories.get('transparent', 0) + categories.get('pid', 0) + categories.get('sysrq', 0) + categories.get('core', 0)} commands")
    print(f"- Performance Monitoring: {categories.get('turbostat', 0) + categories.get('iostat', 0) + categories.get('mpstat', 0) + categories.get('perf', 0) + categories.get('bpftrace', 0) + categories.get('flamegraph', 0) + categories.get('benchmark', 0) + categories.get('zenpower', 0)} commands")
    
    # Verify AMD optimization count
    amd_optimized = sum(1 for cmd in PERFORMANCE_OPTIMIZATION_COMMANDS if cmd.get('amd_ryzen_optimized', False))
    print(f"\nAMD Ryzen 7 7800X3D optimized commands: {amd_optimized}")
    
    # Save to JSON
    import json
    with open('performance_optimization_commands_complete.json', 'w') as f:
        json.dump(PERFORMANCE_OPTIMIZATION_COMMANDS, f, indent=2)