#!/usr/bin/env python3
"""
Advanced System Metrics Collector
Comprehensive system-level performance monitoring
"""

import time
import logging
import threading
import psutil
import platform
import subprocess
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from collections import defaultdict
import json

from ..metrics_collector import MetricValue

logger = logging.getLogger(__name__)

@dataclass
class SystemInfo:
    """System information container"""
    hostname: str
    platform: str
    architecture: str
    cpu_count: int
    memory_total: int
    boot_time: float
    python_version: str

class AdvancedSystemMetricsCollector:
    """Advanced system metrics collector with detailed hardware monitoring"""
    
    def __init__(self):
        self.system_info = self._get_system_info()
        self.previous_readings = {}
        self.collection_errors = defaultdict(int)
        
        # Platform-specific initialization
        self.is_linux = platform.system() == "Linux"
        self.is_windows = platform.system() == "Windows"
        self.is_macos = platform.system() == "Darwin"
        
        logger.info(f"Initialized system metrics collector for {self.system_info.platform}")
    
    def _get_system_info(self) -> SystemInfo:
        """Get static system information"""
        import sys
        
        return SystemInfo(
            hostname=platform.node(),
            platform=platform.system(),
            architecture=platform.architecture()[0],
            cpu_count=psutil.cpu_count(logical=True),
            memory_total=psutil.virtual_memory().total,
            boot_time=psutil.boot_time(),
            python_version=sys.version
        )
    
    def collect_all_metrics(self) -> List[MetricValue]:
        """Collect all system metrics"""
        timestamp = time.time()
        metrics = []
        
        try:
            # Core system metrics
            metrics.extend(self._collect_cpu_metrics(timestamp))
            metrics.extend(self._collect_memory_metrics(timestamp))
            metrics.extend(self._collect_disk_metrics(timestamp))
            metrics.extend(self._collect_network_metrics(timestamp))
            metrics.extend(self._collect_process_metrics(timestamp))
            
            # Advanced system metrics
            metrics.extend(self._collect_thermal_metrics(timestamp))
            metrics.extend(self._collect_power_metrics(timestamp))
            metrics.extend(self._collect_system_load_metrics(timestamp))
            metrics.extend(self._collect_file_system_metrics(timestamp))
            
            # Platform-specific metrics
            if self.is_linux:
                metrics.extend(self._collect_linux_specific_metrics(timestamp))
            elif self.is_windows:
                metrics.extend(self._collect_windows_specific_metrics(timestamp))
            elif self.is_macos:
                metrics.extend(self._collect_macos_specific_metrics(timestamp))
            
            # System health indicators
            metrics.extend(self._collect_health_indicators(timestamp))
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            self.collection_errors['general'] += 1
        
        return metrics
    
    def _collect_cpu_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect detailed CPU metrics"""
        metrics = []
        
        try:
            # Overall CPU usage
            cpu_percent = psutil.cpu_percent(interval=None)
            metrics.append(MetricValue(
                name="cpu_usage_percent_total",
                value=cpu_percent,
                timestamp=timestamp,
                source="system",
                tags={"type": "cpu", "measurement": "usage"}
            ))
            
            # Per-core CPU usage
            cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
            for i, core_usage in enumerate(cpu_per_core):
                metrics.append(MetricValue(
                    name="cpu_usage_percent_core",
                    value=core_usage,
                    timestamp=timestamp,
                    source="system",
                    tags={"type": "cpu", "core": str(i), "measurement": "usage"}
                ))
            
            # CPU frequency
            try:
                cpu_freq = psutil.cpu_freq()
                if cpu_freq:
                    metrics.extend([
                        MetricValue("cpu_frequency_current_mhz", cpu_freq.current, timestamp,
                                  source="system", tags={"type": "cpu", "measurement": "frequency"}),
                        MetricValue("cpu_frequency_min_mhz", cpu_freq.min, timestamp,
                                  source="system", tags={"type": "cpu", "measurement": "frequency"}),
                        MetricValue("cpu_frequency_max_mhz", cpu_freq.max, timestamp,
                                  source="system", tags={"type": "cpu", "measurement": "frequency"})
                    ])
                
                # Per-core frequencies
                cpu_freq_per_core = psutil.cpu_freq(percpu=True)
                for i, freq in enumerate(cpu_freq_per_core):
                    if freq:
                        metrics.append(MetricValue(
                            name="cpu_frequency_core_mhz",
                            value=freq.current,
                            timestamp=timestamp,
                            source="system",
                            tags={"type": "cpu", "core": str(i), "measurement": "frequency"}
                        ))
            except Exception as e:
                logger.debug(f"CPU frequency collection error: {e}")
            
            # Load averages (Unix-like systems)
            try:
                load_avg = psutil.getloadavg()
                for i, period in enumerate(['1min', '5min', '15min']):
                    metrics.append(MetricValue(
                        name="system_load_average",
                        value=load_avg[i],
                        timestamp=timestamp,
                        source="system",
                        tags={"type": "load", "period": period}
                    ))
            except AttributeError:
                pass  # Windows doesn't have load averages
            
            # CPU times
            cpu_times = psutil.cpu_times()
            cpu_time_metrics = {
                'user': cpu_times.user,
                'system': cpu_times.system,
                'idle': cpu_times.idle
            }
            
            # Optional CPU time fields
            for attr in ['nice', 'iowait', 'irq', 'softirq', 'steal', 'guest', 'guest_nice']:
                if hasattr(cpu_times, attr):
                    cpu_time_metrics[attr] = getattr(cpu_times, attr)
            
            for time_type, time_value in cpu_time_metrics.items():
                metrics.append(MetricValue(
                    name="cpu_time_seconds",
                    value=time_value,
                    timestamp=timestamp,
                    source="system",
                    tags={"type": "cpu", "time_type": time_type}
                ))
            
            # CPU context switches and interrupts
            cpu_stats = psutil.cpu_stats()
            metrics.extend([
                MetricValue("cpu_context_switches_total", cpu_stats.ctx_switches, timestamp,
                          source="system", tags={"type": "cpu", "measurement": "context_switches"}),
                MetricValue("cpu_interrupts_total", cpu_stats.interrupts, timestamp,
                          source="system", tags={"type": "cpu", "measurement": "interrupts"}),
                MetricValue("cpu_soft_interrupts_total", cpu_stats.soft_interrupts, timestamp,
                          source="system", tags={"type": "cpu", "measurement": "soft_interrupts"})
            ])
            
            # System calls (if available)
            if hasattr(cpu_stats, 'syscalls'):
                metrics.append(MetricValue(
                    "cpu_syscalls_total", cpu_stats.syscalls, timestamp,
                    source="system", tags={"type": "cpu", "measurement": "syscalls"}
                ))
        
        except Exception as e:
            logger.error(f"CPU metrics collection error: {e}")
            self.collection_errors['cpu'] += 1
        
        return metrics
    
    def _collect_memory_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect detailed memory metrics"""
        metrics = []
        
        try:
            # Virtual memory
            vm = psutil.virtual_memory()
            vm_metrics = {
                'total': vm.total,
                'available': vm.available,
                'used': vm.used,
                'free': vm.free,
                'percent': vm.percent
            }
            
            # Optional virtual memory fields
            for attr in ['active', 'inactive', 'buffers', 'cached', 'shared', 'slab']:
                if hasattr(vm, attr):
                    vm_metrics[attr] = getattr(vm, attr)
            
            for metric_name, value in vm_metrics.items():
                metrics.append(MetricValue(
                    name=f"memory_{metric_name}",
                    value=value,
                    timestamp=timestamp,
                    source="system",
                    tags={"type": "memory", "memory_type": "virtual"}
                ))
            
            # Swap memory
            swap = psutil.swap_memory()
            swap_metrics = {
                'total': swap.total,
                'used': swap.used,
                'free': swap.free,
                'percent': swap.percent,
                'sin': swap.sin,
                'sout': swap.sout
            }
            
            for metric_name, value in swap_metrics.items():
                metrics.append(MetricValue(
                    name=f"swap_{metric_name}",
                    value=value,
                    timestamp=timestamp,
                    source="system",
                    tags={"type": "memory", "memory_type": "swap"}
                ))
        
        except Exception as e:
            logger.error(f"Memory metrics collection error: {e}")
            self.collection_errors['memory'] += 1
        
        return metrics
    
    def _collect_disk_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect detailed disk metrics"""
        metrics = []
        
        try:
            # Disk usage for all mounted filesystems
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    device = partition.device.replace('/', '_').replace('\\', '_').replace(':', '')
                    
                    disk_metrics = {
                        'total_bytes': usage.total,
                        'used_bytes': usage.used,
                        'free_bytes': usage.free,
                        'usage_percent': (usage.used / usage.total) * 100 if usage.total > 0 else 0
                    }
                    
                    for metric_name, value in disk_metrics.items():
                        metrics.append(MetricValue(
                            name=f"disk_{metric_name}",
                            value=value,
                            timestamp=timestamp,
                            source="system",
                            tags={
                                "type": "disk",
                                "device": device,
                                "mountpoint": partition.mountpoint,
                                "fstype": partition.fstype
                            }
                        ))
                
                except (PermissionError, OSError, FileNotFoundError):
                    continue
            
            # Disk I/O statistics
            try:
                disk_io = psutil.disk_io_counters()
                if disk_io:
                    io_metrics = {
                        'read_count': disk_io.read_count,
                        'write_count': disk_io.write_count,
                        'read_bytes': disk_io.read_bytes,
                        'write_bytes': disk_io.write_bytes,
                        'read_time': disk_io.read_time,
                        'write_time': disk_io.write_time
                    }
                    
                    # Optional fields
                    for attr in ['busy_time', 'read_merged_count', 'write_merged_count']:
                        if hasattr(disk_io, attr):
                            io_metrics[attr] = getattr(disk_io, attr)
                    
                    for metric_name, value in io_metrics.items():
                        metrics.append(MetricValue(
                            name=f"disk_io_{metric_name}",
                            value=value,
                            timestamp=timestamp,
                            source="system",
                            tags={"type": "disk_io"}
                        ))
                
                # Per-device I/O statistics
                disk_io_per_device = psutil.disk_io_counters(perdisk=True)
                for device, io_stats in disk_io_per_device.items():
                    device_clean = device.replace('/', '_').replace('\\', '_')
                    
                    device_metrics = {
                        'read_count': io_stats.read_count,
                        'write_count': io_stats.write_count,
                        'read_bytes': io_stats.read_bytes,
                        'write_bytes': io_stats.write_bytes
                    }
                    
                    for metric_name, value in device_metrics.items():
                        metrics.append(MetricValue(
                            name=f"disk_device_{metric_name}",
                            value=value,
                            timestamp=timestamp,
                            source="system",
                            tags={"type": "disk_io", "device": device_clean}
                        ))
            
            except Exception as e:
                logger.debug(f"Disk I/O collection error: {e}")
        
        except Exception as e:
            logger.error(f"Disk metrics collection error: {e}")
            self.collection_errors['disk'] += 1
        
        return metrics
    
    def _collect_network_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect detailed network metrics"""
        metrics = []
        
        try:
            # Network I/O statistics
            net_io = psutil.net_io_counters()
            if net_io:
                io_metrics = {
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv,
                    'errin': net_io.errin,
                    'errout': net_io.errout,
                    'dropin': net_io.dropin,
                    'dropout': net_io.dropout
                }
                
                for metric_name, value in io_metrics.items():
                    metrics.append(MetricValue(
                        name=f"network_{metric_name}",
                        value=value,
                        timestamp=timestamp,
                        source="system",
                        tags={"type": "network_io"}
                    ))
            
            # Per-interface network statistics
            net_io_per_interface = psutil.net_io_counters(pernic=True)
            for interface, io_stats in net_io_per_interface.items():
                interface_metrics = {
                    'bytes_sent': io_stats.bytes_sent,
                    'bytes_recv': io_stats.bytes_recv,
                    'packets_sent': io_stats.packets_sent,
                    'packets_recv': io_stats.packets_recv
                }
                
                for metric_name, value in interface_metrics.items():
                    metrics.append(MetricValue(
                        name=f"network_interface_{metric_name}",
                        value=value,
                        timestamp=timestamp,
                        source="system",
                        tags={"type": "network_io", "interface": interface}
                    ))
            
            # Network connections
            try:
                connections = psutil.net_connections()
                connection_states = defaultdict(int)
                connection_families = defaultdict(int)
                connection_types = defaultdict(int)
                
                for conn in connections:
                    if conn.status:
                        connection_states[conn.status] += 1
                    if conn.family:
                        family_name = str(conn.family).split('.')[-1]
                        connection_families[family_name] += 1
                    if conn.type:
                        type_name = str(conn.type).split('.')[-1]
                        connection_types[type_name] += 1
                
                # Connection state metrics
                for state, count in connection_states.items():
                    metrics.append(MetricValue(
                        name="network_connections_by_state",
                        value=count,
                        timestamp=timestamp,
                        source="system",
                        tags={"type": "network_connections", "state": state}
                    ))
                
                # Connection family metrics
                for family, count in connection_families.items():
                    metrics.append(MetricValue(
                        name="network_connections_by_family",
                        value=count,
                        timestamp=timestamp,
                        source="system",
                        tags={"type": "network_connections", "family": family}
                    ))
                
                # Total connections
                metrics.append(MetricValue(
                    name="network_connections_total",
                    value=len(connections),
                    timestamp=timestamp,
                    source="system",
                    tags={"type": "network_connections"}
                ))
            
            except (psutil.AccessDenied, OSError):
                pass  # May not have permission to read all connections
        
        except Exception as e:
            logger.error(f"Network metrics collection error: {e}")
            self.collection_errors['network'] += 1
        
        return metrics
    
    def _collect_process_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect process-related metrics"""
        metrics = []
        
        try:
            # Current process metrics
            current_process = psutil.Process()
            
            # Memory information
            memory_info = current_process.memory_info()
            memory_metrics = {
                'rss_bytes': memory_info.rss,
                'vms_bytes': memory_info.vms
            }
            
            # Optional memory fields
            for attr in ['shared', 'text', 'data', 'lib', 'dirty']:
                if hasattr(memory_info, attr):
                    memory_metrics[f'{attr}_bytes'] = getattr(memory_info, attr)
            
            for metric_name, value in memory_metrics.items():
                metrics.append(MetricValue(
                    name=f"process_memory_{metric_name}",
                    value=value,
                    timestamp=timestamp,
                    source="system",
                    tags={"type": "process", "measurement": "memory"}
                ))
            
            # Memory percentage
            try:
                memory_percent = current_process.memory_percent()
                metrics.append(MetricValue(
                    name="process_memory_percent",
                    value=memory_percent,
                    timestamp=timestamp,
                    source="system",
                    tags={"type": "process", "measurement": "memory"}
                ))
            except Exception:
                pass
            
            # CPU metrics
            cpu_percent = current_process.cpu_percent()
            metrics.append(MetricValue(
                name="process_cpu_percent",
                value=cpu_percent,
                timestamp=timestamp,
                source="system",
                tags={"type": "process", "measurement": "cpu"}
            ))
            
            # Thread and file descriptor counts
            thread_count = current_process.num_threads()
            metrics.append(MetricValue(
                name="process_thread_count",
                value=thread_count,
                timestamp=timestamp,
                source="system",
                tags={"type": "process", "measurement": "threads"}
            ))
            
            try:
                fd_count = current_process.num_fds()
                metrics.append(MetricValue(
                    name="process_file_descriptors",
                    value=fd_count,
                    timestamp=timestamp,
                    source="system",
                    tags={"type": "process", "measurement": "file_descriptors"}
                ))
            except AttributeError:
                pass  # Windows doesn't have file descriptors
            
            # System-wide process metrics
            process_count = len(psutil.pids())
            metrics.append(MetricValue(
                name="system_process_count",
                value=process_count,
                timestamp=timestamp,
                source="system",
                tags={"type": "system", "measurement": "processes"}
            ))
            
            # Process states
            process_states = defaultdict(int)
            for pid in psutil.pids():
                try:
                    proc = psutil.Process(pid)
                    status = proc.status()
                    process_states[status] += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            for state, count in process_states.items():
                metrics.append(MetricValue(
                    name="system_processes_by_state",
                    value=count,
                    timestamp=timestamp,
                    source="system",
                    tags={"type": "system", "process_state": state}
                ))
        
        except Exception as e:
            logger.error(f"Process metrics collection error: {e}")
            self.collection_errors['process'] += 1
        
        return metrics
    
    def _collect_thermal_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect thermal/temperature metrics"""
        metrics = []
        
        try:
            sensors = psutil.sensors_temperatures()
            for sensor_name, temps in sensors.items():
                for i, temp in enumerate(temps):
                    if temp.current is not None:
                        metrics.append(MetricValue(
                            name="system_temperature_celsius",
                            value=temp.current,
                            timestamp=timestamp,
                            source="system",
                            tags={
                                "type": "thermal",
                                "sensor": sensor_name,
                                "sensor_id": str(i),
                                "label": temp.label or f"sensor_{i}"
                            }
                        ))
                        
                        # High and critical temperature thresholds
                        if temp.high is not None:
                            metrics.append(MetricValue(
                                name="system_temperature_high_threshold",
                                value=temp.high,
                                timestamp=timestamp,
                                source="system",
                                tags={
                                    "type": "thermal",
                                    "sensor": sensor_name,
                                    "sensor_id": str(i)
                                }
                            ))
                        
                        if temp.critical is not None:
                            metrics.append(MetricValue(
                                name="system_temperature_critical_threshold",
                                value=temp.critical,
                                timestamp=timestamp,
                                source="system",
                                tags={
                                    "type": "thermal",
                                    "sensor": sensor_name,
                                    "sensor_id": str(i)
                                }
                            ))
        
        except Exception as e:
            logger.debug(f"Thermal metrics collection error: {e}")
            # Temperature sensors may not be available on all systems
        
        return metrics
    
    def _collect_power_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect power/battery metrics"""
        metrics = []
        
        try:
            # Battery information
            battery = psutil.sensors_battery()
            if battery:
                metrics.extend([
                    MetricValue("system_battery_percent", battery.percent, timestamp,
                              source="system", tags={"type": "power", "measurement": "battery"}),
                    MetricValue("system_battery_plugged", int(battery.power_plugged), timestamp,
                              source="system", tags={"type": "power", "measurement": "power_source"})
                ])
                
                if battery.secsleft != psutil.POWER_TIME_UNKNOWN:
                    metrics.append(MetricValue(
                        "system_battery_time_left_seconds", battery.secsleft, timestamp,
                        source="system", tags={"type": "power", "measurement": "battery"}
                    ))
        
        except Exception as e:
            logger.debug(f"Power metrics collection error: {e}")
            # Power information may not be available on all systems
        
        return metrics
    
    def _collect_system_load_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect system load and performance metrics"""
        metrics = []
        
        try:
            # Boot time and uptime
            boot_time = psutil.boot_time()
            uptime = timestamp - boot_time
            
            metrics.extend([
                MetricValue("system_boot_time", boot_time, timestamp,
                          source="system", tags={"type": "system", "measurement": "boot_time"}),
                MetricValue("system_uptime_seconds", uptime, timestamp,
                          source="system", tags={"type": "system", "measurement": "uptime"})
            ])
            
            # Users logged in
            users = psutil.users()
            metrics.append(MetricValue(
                "system_users_logged_in", len(users), timestamp,
                source="system", tags={"type": "system", "measurement": "users"}
            ))
            
            # Unique users
            unique_users = len(set(user.name for user in users))
            metrics.append(MetricValue(
                "system_unique_users_logged_in", unique_users, timestamp,
                source="system", tags={"type": "system", "measurement": "users"}
            ))
        
        except Exception as e:
            logger.error(f"System load metrics collection error: {e}")
            self.collection_errors['system_load'] += 1
        
        return metrics
    
    def _collect_file_system_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect file system related metrics"""
        metrics = []
        
        try:
            # Open files by the current process
            current_process = psutil.Process()
            try:
                open_files = current_process.open_files()
                metrics.append(MetricValue(
                    "process_open_files_count", len(open_files), timestamp,
                    source="system", tags={"type": "filesystem", "measurement": "open_files"}
                ))
            except (psutil.AccessDenied, OSError):
                pass
            
            # System-wide file descriptor usage (Linux-specific)
            if self.is_linux:
                try:
                    with open('/proc/sys/fs/file-nr', 'r') as f:
                        file_info = f.read().strip().split()
                        if len(file_info) >= 3:
                            metrics.extend([
                                MetricValue("system_open_files_total", int(file_info[0]), timestamp,
                                          source="system", tags={"type": "filesystem"}),
                                MetricValue("system_free_file_handles", int(file_info[1]), timestamp,
                                          source="system", tags={"type": "filesystem"}),
                                MetricValue("system_max_file_handles", int(file_info[2]), timestamp,
                                          source="system", tags={"type": "filesystem"})
                            ])
                except (IOError, ValueError, IndexError):
                    pass
        
        except Exception as e:
            logger.error(f"File system metrics collection error: {e}")
            self.collection_errors['filesystem'] += 1
        
        return metrics
    
    def _collect_linux_specific_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect Linux-specific metrics"""
        metrics = []
        
        try:
            # Memory information from /proc/meminfo
            try:
                with open('/proc/meminfo', 'r') as f:
                    meminfo = {}
                    for line in f:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip()
                            value = value.strip().split()[0]  # Remove 'kB' unit
                            try:
                                meminfo[key] = int(value) * 1024  # Convert to bytes
                            except ValueError:
                                pass
                
                for key, value in meminfo.items():
                    metrics.append(MetricValue(
                        name=f"linux_memory_{key.lower()}",
                        value=value,
                        timestamp=timestamp,
                        source="system",
                        tags={"type": "memory", "source": "proc_meminfo"}
                    ))
            
            except IOError:
                pass
            
            # CPU information from /proc/stat
            try:
                with open('/proc/stat', 'r') as f:
                    lines = f.readlines()
                    
                for line in lines:
                    if line.startswith('cpu '):
                        # Global CPU statistics
                        parts = line.split()[1:]  # Skip 'cpu' label
                        cpu_times = ['user', 'nice', 'system', 'idle', 'iowait', 'irq', 'softirq', 'steal']
                        for i, time_type in enumerate(cpu_times):
                            if i < len(parts):
                                metrics.append(MetricValue(
                                    name=f"linux_cpu_time_{time_type}",
                                    value=int(parts[i]),
                                    timestamp=timestamp,
                                    source="system",
                                    tags={"type": "cpu", "source": "proc_stat"}
                                ))
                        break
            
            except IOError:
                pass
            
            # Load average from /proc/loadavg
            try:
                with open('/proc/loadavg', 'r') as f:
                    loadavg = f.read().split()
                    if len(loadavg) >= 3:
                        for i, period in enumerate(['1min', '5min', '15min']):
                            metrics.append(MetricValue(
                                name="linux_load_average",
                                value=float(loadavg[i]),
                                timestamp=timestamp,
                                source="system",
                                tags={"type": "load", "period": period, "source": "proc_loadavg"}
                            ))
            
            except (IOError, ValueError):
                pass
        
        except Exception as e:
            logger.error(f"Linux-specific metrics collection error: {e}")
            self.collection_errors['linux_specific'] += 1
        
        return metrics
    
    def _collect_windows_specific_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect Windows-specific metrics"""
        metrics = []
        
        try:
            # Windows performance counters could be added here
            # This would require additional libraries like pywin32
            pass
        
        except Exception as e:
            logger.error(f"Windows-specific metrics collection error: {e}")
            self.collection_errors['windows_specific'] += 1
        
        return metrics
    
    def _collect_macos_specific_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect macOS-specific metrics"""
        metrics = []
        
        try:
            # macOS-specific system information could be added here
            # This might involve system_profiler or other macOS tools
            pass
        
        except Exception as e:
            logger.error(f"macOS-specific metrics collection error: {e}")
            self.collection_errors['macos_specific'] += 1
        
        return metrics
    
    def _collect_health_indicators(self, timestamp: float) -> List[MetricValue]:
        """Collect system health indicators"""
        metrics = []
        
        try:
            # System responsiveness indicator
            start_time = time.time()
            # Simple operation to test system responsiveness
            _ = os.listdir('.')
            responsiveness = time.time() - start_time
            
            metrics.append(MetricValue(
                name="system_responsiveness_seconds",
                value=responsiveness,
                timestamp=timestamp,
                source="system",
                tags={"type": "health", "measurement": "responsiveness"}
            ))
            
            # Memory pressure indicator
            vm = psutil.virtual_memory()
            memory_pressure = vm.percent / 100.0
            metrics.append(MetricValue(
                name="system_memory_pressure",
                value=memory_pressure,
                timestamp=timestamp,
                source="system",
                tags={"type": "health", "measurement": "memory_pressure"}
            ))
            
            # Disk pressure indicator (highest disk usage percentage)
            max_disk_usage = 0
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    usage_percent = (usage.used / usage.total) * 100 if usage.total > 0 else 0
                    max_disk_usage = max(max_disk_usage, usage_percent)
                except (PermissionError, OSError, FileNotFoundError):
                    continue
            
            metrics.append(MetricValue(
                name="system_disk_pressure",
                value=max_disk_usage / 100.0,
                timestamp=timestamp,
                source="system",
                tags={"type": "health", "measurement": "disk_pressure"}
            ))
            
            # Overall system health score (0-1, where 1 is best)
            cpu_health = max(0, 1 - (psutil.cpu_percent() / 100))
            memory_health = max(0, 1 - memory_pressure)
            disk_health = max(0, 1 - (max_disk_usage / 100))
            
            overall_health = (cpu_health + memory_health + disk_health) / 3
            metrics.append(MetricValue(
                name="system_health_score",
                value=overall_health,
                timestamp=timestamp,
                source="system",
                tags={"type": "health", "measurement": "overall_score"}
            ))
        
        except Exception as e:
            logger.error(f"Health indicators collection error: {e}")
            self.collection_errors['health'] += 1
        
        return metrics
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get collection statistics and error counts"""
        return {
            'system_info': {
                'hostname': self.system_info.hostname,
                'platform': self.system_info.platform,
                'architecture': self.system_info.architecture,
                'cpu_count': self.system_info.cpu_count,
                'memory_total_gb': self.system_info.memory_total / (1024**3)
            },
            'collection_errors': dict(self.collection_errors),
            'total_errors': sum(self.collection_errors.values())
        }

# Example usage
if __name__ == "__main__":
    collector = AdvancedSystemMetricsCollector()
    
    print("=== System Information ===")
    stats = collector.get_collection_stats()
    print(json.dumps(stats['system_info'], indent=2))
    
    print("\n=== Collecting Metrics ===")
    metrics = collector.collect_all_metrics()
    
    print(f"Collected {len(metrics)} metrics")
    
    # Show sample metrics
    for metric in metrics[:10]:
        print(f"{metric.name}: {metric.value} (tags: {metric.tags})")
    
    print(f"\nCollection errors: {stats['total_errors']}")
    if stats['collection_errors']:
        for category, count in stats['collection_errors'].items():
            print(f"  {category}: {count}")