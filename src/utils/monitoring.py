"""
Memory and performance monitoring module for comprehensive system analysis.

This module consolidates functionality from memory analysis scripts:
- analyze_memory_usage.py
- memory profiling tools
- performance monitoring utilities

Provides unified interface for memory analysis, performance monitoring,
and resource tracking following enterprise monitoring standards.
"""

import psutil
import tracemalloc
import gc
import sys
import time
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import threading
import asyncio
import weakref

logger = logging.getLogger(__name__)


@dataclass
class MemorySnapshot:
    """Represents a memory usage snapshot at a point in time."""
    timestamp: datetime
    process_memory_mb: float
    process_memory_percent: float
    system_memory_mb: float
    system_memory_percent: float
    virtual_memory_mb: float
    swap_memory_mb: float
    swap_memory_percent: float
    gc_stats: Dict[str, int] = field(default_factory=dict)
    top_allocations: List[Dict[str, Any]] = field(default_factory=list)
    
    
@dataclass
class MemoryLeak:
    """Represents a potential memory leak."""
    location: str
    size_mb: float
    growth_rate_mb_per_min: float
    allocation_count: int
    traceback: List[str]
    severity: str  # low, medium, high, critical
    
    
@dataclass
class PerformanceMetrics:
    """Performance metrics for a specific operation or time period."""
    operation: str
    start_time: datetime
    end_time: datetime
    duration_ms: float
    cpu_percent: float
    memory_delta_mb: float
    io_read_mb: float
    io_write_mb: float
    context_switches: int
    thread_count: int
    exceptions_raised: int = 0
    

class MemoryAnalyzer:
    """
    Comprehensive memory analysis and performance monitoring.
    
    Consolidates memory analysis functionality into a unified,
    production-ready monitoring solution.
    """
    
    def __init__(self, 
                 track_allocations: bool = False,
                 snapshot_interval: int = 60,
                 max_snapshots: int = 1000):
        """
        Initialize MemoryAnalyzer.
        
        Args:
            track_allocations: Enable detailed allocation tracking
            snapshot_interval: Seconds between automatic snapshots
            max_snapshots: Maximum snapshots to retain
        """
        self.track_allocations = track_allocations
        self.snapshot_interval = snapshot_interval
        self.max_snapshots = max_snapshots
        
        self.snapshots: List[MemorySnapshot] = []
        self.performance_metrics: List[PerformanceMetrics] = []
        self.memory_baselines: Dict[str, float] = {}
        self.leak_candidates: List[MemoryLeak] = []
        
        self._monitoring_thread: Optional[threading.Thread] = None
        self._stop_monitoring = threading.Event()
        self._allocation_tracker: Optional[tracemalloc.Snapshot] = None
        
        # Object tracking for leak detection
        self._object_tracker: weakref.WeakValueDictionary = weakref.WeakValueDictionary()
        self._object_counts: Dict[type, int] = defaultdict(int)
        
        if self.track_allocations:
            tracemalloc.start()
            
    def start_monitoring(self):
        """Start continuous memory monitoring in background thread."""
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            logger.warning("Monitoring already active")
            return
            
        self._stop_monitoring.clear()
        self._monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True
        )
        self._monitoring_thread.start()
        logger.info("Memory monitoring started")
        
    def stop_monitoring(self):
        """Stop continuous memory monitoring."""
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            self._stop_monitoring.set()
            self._monitoring_thread.join(timeout=5)
            logger.info("Memory monitoring stopped")
            
    def _monitoring_loop(self):
        """Background monitoring loop."""
        while not self._stop_monitoring.is_set():
            try:
                snapshot = self.capture_snapshot()
                self.snapshots.append(snapshot)
                
                # Trim old snapshots
                if len(self.snapshots) > self.max_snapshots:
                    self.snapshots = self.snapshots[-self.max_snapshots:]
                    
                # Check for memory leaks
                if len(self.snapshots) >= 5:
                    self.detect_memory_leaks()
                    
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                
            self._stop_monitoring.wait(self.snapshot_interval)
            
    def capture_snapshot(self) -> MemorySnapshot:
        """
        Capture current memory usage snapshot.
        
        Returns:
            MemorySnapshot with current memory state
        """
        process = psutil.Process()
        memory_info = process.memory_info()
        memory_percent = process.memory_percent()
        
        # System memory
        virtual_memory = psutil.virtual_memory()
        swap_memory = psutil.swap_memory()
        
        # GC stats
        gc_stats = {
            f"generation_{i}": gc.get_count()[i] 
            for i in range(gc.get_count().__len__())
        }
        gc_stats['objects'] = len(gc.get_objects())
        
        snapshot = MemorySnapshot(
            timestamp=datetime.now(),
            process_memory_mb=memory_info.rss / 1024 / 1024,
            process_memory_percent=memory_percent,
            system_memory_mb=virtual_memory.used / 1024 / 1024,
            system_memory_percent=virtual_memory.percent,
            virtual_memory_mb=memory_info.vms / 1024 / 1024,
            swap_memory_mb=swap_memory.used / 1024 / 1024,
            swap_memory_percent=swap_memory.percent,
            gc_stats=gc_stats
        )
        
        # Get top memory allocations if tracking
        if self.track_allocations and tracemalloc.is_tracing():
            snapshot.top_allocations = self._get_top_allocations(10)
            
        return snapshot
        
    def _get_top_allocations(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top memory allocations."""
        allocations = []
        
        snapshot = tracemalloc.take_snapshot()
        top_stats = snapshot.statistics('lineno')
        
        for stat in top_stats[:limit]:
            allocations.append({
                'file': stat.traceback.format()[0] if stat.traceback else 'Unknown',
                'size_mb': stat.size / 1024 / 1024,
                'count': stat.count,
                'average_size': stat.size / stat.count if stat.count > 0 else 0
            })
            
        return allocations
        
    def analyze_memory_usage(self, 
                           detailed: bool = True) -> Dict[str, Any]:
        """
        Analyze current memory usage patterns.
        
        Args:
            detailed: Include detailed analysis
            
        Returns:
            Dictionary with memory analysis results
        """
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'summary': {},
            'process': {},
            'system': {},
            'gc': {},
            'trends': {}
        }
        
        # Current snapshot
        current = self.capture_snapshot()
        
        # Process memory
        process = psutil.Process()
        memory_info = process.memory_full_info()
        
        analysis['process'] = {
            'rss_mb': memory_info.rss / 1024 / 1024,
            'vms_mb': memory_info.vms / 1024 / 1024,
            'shared_mb': memory_info.shared / 1024 / 1024 if hasattr(memory_info, 'shared') else 0,
            'unique_mb': (memory_info.rss - getattr(memory_info, 'shared', 0)) / 1024 / 1024,
            'percent': process.memory_percent(),
            'num_threads': process.num_threads(),
            'num_fds': process.num_fds() if hasattr(process, 'num_fds') else 0
        }
        
        # System memory
        virtual_memory = psutil.virtual_memory()
        analysis['system'] = {
            'total_mb': virtual_memory.total / 1024 / 1024,
            'available_mb': virtual_memory.available / 1024 / 1024,
            'used_mb': virtual_memory.used / 1024 / 1024,
            'free_mb': virtual_memory.free / 1024 / 1024,
            'percent': virtual_memory.percent
        }
        
        # GC analysis
        analysis['gc'] = current.gc_stats.copy()
        analysis['gc']['thresholds'] = gc.get_threshold()
        analysis['gc']['is_enabled'] = gc.isenabled()
        
        # Analyze trends if we have history
        if len(self.snapshots) >= 2:
            analysis['trends'] = self._analyze_trends()
            
        # Detailed analysis
        if detailed:
            analysis['top_types'] = self._analyze_object_types()
            analysis['memory_map'] = self._get_memory_map()
            
            if self.track_allocations:
                analysis['top_allocations'] = current.top_allocations
                analysis['allocation_stats'] = self._get_allocation_stats()
                
        # Summary
        analysis['summary'] = {
            'process_memory_mb': analysis['process']['rss_mb'],
            'memory_percent': analysis['process']['percent'],
            'growth_rate_mb_per_hour': analysis['trends'].get('memory_growth_rate', 0) * 60,
            'estimated_leak': len(self.leak_candidates) > 0,
            'gc_pressure': analysis['gc']['objects'] > 100000
        }
        
        return analysis
        
    def _analyze_trends(self) -> Dict[str, float]:
        """Analyze memory usage trends."""
        if len(self.snapshots) < 2:
            return {}
            
        # Calculate growth rates
        first_snapshot = self.snapshots[0]
        last_snapshot = self.snapshots[-1]
        time_diff_minutes = (last_snapshot.timestamp - first_snapshot.timestamp).total_seconds() / 60
        
        if time_diff_minutes == 0:
            return {}
            
        memory_growth = last_snapshot.process_memory_mb - first_snapshot.process_memory_mb
        growth_rate = memory_growth / time_diff_minutes
        
        # Calculate average and peak
        memory_values = [s.process_memory_mb for s in self.snapshots]
        
        return {
            'memory_growth_rate': growth_rate,  # MB per minute
            'memory_growth_total': memory_growth,
            'memory_average': sum(memory_values) / len(memory_values),
            'memory_peak': max(memory_values),
            'memory_min': min(memory_values),
            'time_span_minutes': time_diff_minutes
        }
        
    def _analyze_object_types(self) -> List[Dict[str, Any]]:
        """Analyze object types in memory."""
        type_counts = defaultdict(int)
        type_sizes = defaultdict(int)
        
        for obj in gc.get_objects():
            obj_type = type(obj)
            type_counts[obj_type] += 1
            
            try:
                # Estimate size (simplified - real implementation would be more thorough)
                size = sys.getsizeof(obj)
                type_sizes[obj_type] += size
            except:
                pass
                
        # Get top types by count
        top_types = []
        for obj_type, count in sorted(type_counts.items(), 
                                     key=lambda x: x[1], 
                                     reverse=True)[:20]:
            top_types.append({
                'type': f"{obj_type.__module__}.{obj_type.__name__}",
                'count': count,
                'total_size_mb': type_sizes[obj_type] / 1024 / 1024,
                'average_size_bytes': type_sizes[obj_type] / count if count > 0 else 0
            })
            
        return top_types
        
    def _get_memory_map(self) -> List[Dict[str, Any]]:
        """Get process memory map."""
        memory_maps = []
        
        try:
            process = psutil.Process()
            for mmap in process.memory_maps():
                memory_maps.append({
                    'path': mmap.path,
                    'rss_mb': mmap.rss / 1024 / 1024,
                    'size_mb': mmap.size / 1024 / 1024 if hasattr(mmap, 'size') else 0,
                    'pss_mb': mmap.pss / 1024 / 1024 if hasattr(mmap, 'pss') else 0,
                    'shared_clean_mb': mmap.shared_clean / 1024 / 1024 if hasattr(mmap, 'shared_clean') else 0,
                    'shared_dirty_mb': mmap.shared_dirty / 1024 / 1024 if hasattr(mmap, 'shared_dirty') else 0
                })
        except Exception as e:
            logger.error(f"Error getting memory map: {e}")
            
        return memory_maps
        
    def _get_allocation_stats(self) -> Dict[str, Any]:
        """Get allocation statistics from tracemalloc."""
        if not tracemalloc.is_tracing():
            return {}
            
        snapshot = tracemalloc.take_snapshot()
        stats = {
            'traced_memory_mb': tracemalloc.get_traced_memory()[0] / 1024 / 1024,
            'peak_memory_mb': tracemalloc.get_traced_memory()[1] / 1024 / 1024,
            'total_blocks': sum(stat.count for stat in snapshot.statistics('filename')),
            'total_size_mb': sum(stat.size for stat in snapshot.statistics('filename')) / 1024 / 1024
        }
        
        # Get top files by memory usage
        top_files = []
        for stat in snapshot.statistics('filename')[:10]:
            top_files.append({
                'file': stat.traceback.format()[0] if stat.traceback else 'Unknown',
                'size_mb': stat.size / 1024 / 1024,
                'count': stat.count
            })
            
        stats['top_files'] = top_files
        
        return stats
        
    def detect_memory_leaks(self) -> List[MemoryLeak]:
        """
        Detect potential memory leaks based on growth patterns.
        
        Returns:
            List of potential memory leaks
        """
        if len(self.snapshots) < 5:
            return []
            
        leaks = []
        
        # Analyze memory growth over time
        memory_values = [(s.timestamp, s.process_memory_mb) for s in self.snapshots[-20:]]
        
        # Simple linear regression to detect consistent growth
        if len(memory_values) >= 5:
            times = [(t[0] - memory_values[0][0]).total_seconds() / 60 for t in memory_values]
            memories = [m[1] for m in memory_values]
            
            # Calculate slope (growth rate)
            n = len(times)
            sum_x = sum(times)
            sum_y = sum(memories)
            sum_xy = sum(x * y for x, y in zip(times, memories))
            sum_x2 = sum(x * x for x in times)
            
            if n * sum_x2 - sum_x * sum_x != 0:
                slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
                
                # If growth rate is significant (> 1 MB/min), flag as potential leak
                if slope > 1.0:
                    # Try to identify source if allocation tracking is enabled
                    location = "Unknown"
                    traceback_lines = []
                    
                    if self.track_allocations and tracemalloc.is_tracing():
                        snapshot = tracemalloc.take_snapshot()
                        top_stats = snapshot.statistics('traceback')
                        
                        if top_stats:
                            top_stat = top_stats[0]
                            location = str(top_stat.traceback)
                            traceback_lines = top_stat.traceback.format()
                            
                    leak = MemoryLeak(
                        location=location,
                        size_mb=memories[-1] - memories[0],
                        growth_rate_mb_per_min=slope,
                        allocation_count=0,
                        traceback=traceback_lines,
                        severity=self._classify_leak_severity(slope)
                    )
                    
                    leaks.append(leak)
                    
        # Check for specific object type growth
        if hasattr(self, '_object_counts'):
            current_counts = self._analyze_object_types()
            
            for type_info in current_counts:
                type_name = type_info['type']
                count = type_info['count']
                
                # Compare with baseline
                if type_name in self.memory_baselines:
                    baseline = self.memory_baselines[type_name]
                    growth = count - baseline
                    
                    # Flag significant growth (>10000 objects)
                    if growth > 10000:
                        leak = MemoryLeak(
                            location=f"Object type: {type_name}",
                            size_mb=type_info['total_size_mb'],
                            growth_rate_mb_per_min=0,  # Unknown
                            allocation_count=growth,
                            traceback=[],
                            severity='medium'
                        )
                        leaks.append(leak)
                else:
                    # Set baseline
                    self.memory_baselines[type_name] = count
                    
        self.leak_candidates = leaks
        return leaks
        
    def _classify_leak_severity(self, growth_rate: float) -> str:
        """Classify leak severity based on growth rate."""
        if growth_rate > 10:
            return 'critical'
        elif growth_rate > 5:
            return 'high'
        elif growth_rate > 2:
            return 'medium'
        else:
            return 'low'
            
    def profile_operation(self, operation_name: str):
        """
        Context manager for profiling a specific operation.
        
        Usage:
            with analyzer.profile_operation('data_processing'):
                # Your code here
                process_data()
        """
        return OperationProfiler(self, operation_name)
        
    def get_memory_report(self, 
                         include_trends: bool = True,
                         include_leaks: bool = True) -> str:
        """
        Generate a human-readable memory report.
        
        Args:
            include_trends: Include trend analysis
            include_leaks: Include leak detection
            
        Returns:
            Formatted memory report
        """
        analysis = self.analyze_memory_usage(detailed=True)
        
        report_lines = [
            "# Memory Analysis Report",
            f"\n**Generated**: {analysis['timestamp']}",\n            "\n## Summary",\n            f"- **Process Memory**: {analysis['summary']['process_memory_mb']:.2f} MB "\n            f"({analysis['summary']['memory_percent']:.1f}%)",\n            f"- **Growth Rate**: {analysis['summary']['growth_rate_mb_per_hour']:.2f} MB/hour",\n            f"- **Potential Leak**: {'Yes' if analysis['summary']['estimated_leak'] else 'No'}",\n            f"- **GC Pressure**: {'High' if analysis['summary']['gc_pressure'] else 'Normal'}",\n            "\n## Process Memory",\n            f"- **RSS**: {analysis['process']['rss_mb']:.2f} MB",\n            f"- **VMS**: {analysis['process']['vms_mb']:.2f} MB",\n            f"- **Shared**: {analysis['process']['shared_mb']:.2f} MB",\n            f"- **Unique**: {analysis['process']['unique_mb']:.2f} MB",\n            f"- **Threads**: {analysis['process']['num_threads']}",\n            "\n## System Memory",\n            f"- **Total**: {analysis['system']['total_mb']:.2f} MB",\n            f"- **Used**: {analysis['system']['used_mb']:.2f} MB ({analysis['system']['percent']:.1f}%)",\n            f"- **Available**: {analysis['system']['available_mb']:.2f} MB",\n            "\n## Garbage Collection",\n            f"- **Objects**: {analysis['gc']['objects']:,}",\n            f"- **Enabled**: {analysis['gc']['is_enabled']}",\n        ]\n\n        # Add generation stats\n        for gen, count in analysis['gc'].items():\n            if gen.startswith('generation_'):\n                report_lines.append(f"- **{gen.replace('_', ' ').title()}**: {count:,}")\n\n        if include_trends and 'trends' in analysis and analysis['trends']:\n            report_lines.extend([\n                "\n## Memory Trends",\n                f"- **Time Span**: {analysis['trends']['time_span_minutes']:.1f} minutes",\n                f"- **Growth Rate**: {analysis['trends']['memory_growth_rate']:.2f} MB/min",\n                f"- **Total Growth**: {analysis['trends']['memory_growth_total']:.2f} MB",\n                f"- **Average**: {analysis['trends']['memory_average']:.2f} MB",\n                f"- **Peak**: {analysis['trends']['memory_peak']:.2f} MB",\n                f"- **Minimum**: {analysis['trends']['memory_min']:.2f} MB",\n            ])\n\n        if 'top_types' in analysis:\n            report_lines.extend([\n                "\n## Top Object Types",\n                "| Type | Count | Total Size (MB) | Avg Size (bytes) |",\n                "|------|-------|----------------|------------------|"\n            ])\n\n            for type_info in analysis['top_types'][:10]:\n                report_lines.append(\n                    f"| {type_info['type']} | {type_info['count']:,} | "\n                    f"{type_info['total_size_mb']:.2f} | {type_info['average_size_bytes']:.0f} |"\n                )\n\n        if include_leaks and self.leak_candidates:\n            report_lines.extend([\n                "\n## Potential Memory Leaks",\n                ""\n            ])\n\n            for i, leak in enumerate(self.leak_candidates, 1):\n                report_lines.extend([\n                    f"### Leak #{i} - {leak.severity.upper()}",\n                    f"- **Location**: {leak.location}",\n                    f"- **Size**: {leak.size_mb:.2f} MB",\n                    f"- **Growth Rate**: {leak.growth_rate_mb_per_min:.2f} MB/min",\n                    ""\n                ])\n\n                if leak.traceback:\n                    report_lines.append("**Traceback**:")\n                    for line in leak.traceback[:5]:\n                        report_lines.append(f"  {line}")\n                    report_lines.append("")\n\n        return '\n'.join(report_lines)\n\n    def export_metrics(self,\n                      output_file: Optional[Path] = None,\n                      format: str = 'json') -> Dict[str, Any]:\n        """\n        Export metrics for external monitoring systems.\n\n        Args:\n            output_file: Optional file to save metrics\n            format: Export format (json, prometheus)\n\n        Returns:\n            Metrics dictionary\n        """\n        metrics = {\n            'timestamp': datetime.now().isoformat(),\n            'memory': {},\n            'performance': [],\n            'leaks': []\n        }\n\n        # Current memory state\n        current = self.capture_snapshot()\n        metrics['memory'] = {\n            'process_memory_bytes': current.process_memory_mb * 1024 * 1024,\n            'process_memory_percent': current.process_memory_percent,\n            'system_memory_bytes': current.system_memory_mb * 1024 * 1024,\n            'system_memory_percent': current.system_memory_percent,\n            'gc_objects': current.gc_stats.get('objects', 0)\n        }\n\n        # Recent performance metrics\n        for perf in self.performance_metrics[-10:]:\n            metrics['performance'].append({\n                'operation': perf.operation,\n                'duration_ms': perf.duration_ms,\n                'memory_delta_mb': perf.memory_delta_mb,\n                'cpu_percent': perf.cpu_percent\n            })\n\n        # Active leaks\n        for leak in self.leak_candidates:\n            metrics['leaks'].append({\n                'location': leak.location,\n                'severity': leak.severity,\n                'growth_rate_mb_per_min': leak.growth_rate_mb_per_min\n            })\n\n        if format == 'prometheus':\n            metrics = self._convert_to_prometheus_format(metrics)\n\n        if output_file:\n            with open(output_file, 'w') as f:\n                if format == 'json':\n                    json.dump(metrics, f, indent=2)\n                else:\n                    f.write(metrics)\n\n        return metrics\n\n    def _convert_to_prometheus_format(self, metrics: Dict[str, Any]) -> str:\n        """Convert metrics to Prometheus format."""\n        lines = []\n\n        # Memory metrics\n        lines.append(f"process_memory_bytes {metrics['memory']['process_memory_bytes']}")\n        lines.append(f"process_memory_percent {metrics['memory']['process_memory_percent']}")\n        lines.append(f"system_memory_bytes {metrics['memory']['system_memory_bytes']}")\n        lines.append(f"system_memory_percent {metrics['memory']['system_memory_percent']}")\n        lines.append(f"gc_objects_total {metrics['memory']['gc_objects']}")\n\n        # Leak metrics\n        leak_count = len(metrics['leaks'])\n        lines.append(f"memory_leaks_total {leak_count}")\n\n        if leak_count > 0:\n            max_growth_rate = max(l['growth_rate_mb_per_min'] for l in metrics['leaks'])\n            lines.append(f"memory_leak_max_growth_rate_mb_per_min {max_growth_rate}")\n\n        return '\n'.join(lines)\n\n\nclass OperationProfiler:\n    """Context manager for profiling operations."""\n\n    def __init__(self, analyzer: MemoryAnalyzer, operation_name: str):\n        self.analyzer = analyzer\n        self.operation_name = operation_name\n        self.start_time = None\n        self.start_memory = None\n        self.start_cpu = None\n        self.start_io = None\n\n    def __enter__(self):\n        """Start profiling."""\n        self.start_time = time.time()\n\n        # Capture starting metrics\n        process = psutil.Process()\n        self.start_memory = process.memory_info().rss / 1024 / 1024\n        self.start_cpu = process.cpu_percent(interval=0.1)\n\n        io_counters = process.io_counters()\n        self.start_io = (io_counters.read_bytes, io_counters.write_bytes)\n\n        return self\n\n    def __exit__(self, exc_type, exc_val, exc_tb):\n        """Stop profiling and record metrics."""\n        end_time = time.time()\n        duration_ms = (end_time - self.start_time) * 1000\n\n        # Capture ending metrics\n        process = psutil.Process()\n        end_memory = process.memory_info().rss / 1024 / 1024\n        end_cpu = process.cpu_percent(interval=0.1)\n\n        io_counters = process.io_counters()\n        end_io = (io_counters.read_bytes, io_counters.write_bytes)\n\n        # Calculate deltas\n        memory_delta = end_memory - self.start_memory\n        io_read = (end_io[0] - self.start_io[0]) / 1024 / 1024\n        io_write = (end_io[1] - self.start_io[1]) / 1024 / 1024\n\n        # Record metrics\n        metrics = PerformanceMetrics(\n            operation=self.operation_name,\n            start_time=datetime.fromtimestamp(self.start_time),\n            end_time=datetime.fromtimestamp(end_time),\n            duration_ms=duration_ms,\n            cpu_percent=(self.start_cpu + end_cpu) / 2,\n            memory_delta_mb=memory_delta,\n            io_read_mb=io_read,\n            io_write_mb=io_write,\n            context_switches=process.num_ctx_switches().voluntary,\n            thread_count=process.num_threads(),\n            exceptions_raised=1 if exc_type else 0\n        )\n\n        self.analyzer.performance_metrics.append(metrics)\n\n        # Log if significant resource usage\n        if duration_ms > 1000 or abs(memory_delta) > 100:\n            logger.info(\n                f"Operation '{self.operation_name}' completed: "\n                f"{duration_ms:.1f}ms, {memory_delta:+.1f}MB, "\n                f"{end_cpu:.1f}% CPU"\n            )\n\n\n# CLI interface for backward compatibility\ndef main():\n    """Command-line interface for memory analysis."""\n    import argparse\n\n    parser = argparse.ArgumentParser(description="Memory analysis and monitoring tool")\n\n    subparsers = parser.add_subparsers(dest='command', help='Command to run')\n\n    # Analyze command\n    analyze_parser = subparsers.add_parser('analyze', help='Analyze current memory usage')\n    analyze_parser.add_argument('--detailed', action='store_true',\n                               help='Include detailed analysis')\n    analyze_parser.add_argument('--output', '-o', help='Output file for report')\n\n    # Monitor command\n    monitor_parser = subparsers.add_parser('monitor', help='Start continuous monitoring')\n    monitor_parser.add_argument('--interval', type=int, default=60,\n                               help='Snapshot interval in seconds')\n    monitor_parser.add_argument('--duration', type=int,\n                               help='Monitoring duration in seconds')\n\n    # Detect command\n    detect_parser = subparsers.add_parser('detect', help='Detect memory leaks')\n    detect_parser.add_argument('--threshold', type=float, default=1.0,\n                              help='Growth rate threshold (MB/min)')\n\n    # Export command\n    export_parser = subparsers.add_parser('export', help='Export metrics')\n    export_parser.add_argument('--format', choices=['json', 'prometheus'],\n                              default='json', help='Export format')\n    export_parser.add_argument('--output', '-o', help='Output file')\n\n    args = parser.parse_args()\n\n    # Configure logging\n    logging.basicConfig(level=logging.INFO,\n                       format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')\n\n    analyzer = MemoryAnalyzer(track_allocations=True)\n\n    if args.command == 'analyze':\n        analysis = analyzer.analyze_memory_usage(detailed=args.detailed)\n        report = analyzer.get_memory_report()\n\n        print(report)\n\n        if args.output:\n            with open(args.output, 'w') as f:\n                f.write(report)\n            print(f"\n✅ Report saved to: {args.output}")\n\n    elif args.command == 'monitor':\n        print(f"📊 Starting memory monitoring (interval: {args.interval}s)...")\n        analyzer.start_monitoring()\n\n        try:\n            if args.duration:\n                time.sleep(args.duration)\n            else:\n                print("Press Ctrl+C to stop monitoring...")\n                while True:\n                    time.sleep(1)\n        except KeyboardInterrupt:\n            pass\n        finally:\n            analyzer.stop_monitoring()\n\n        # Show summary\n        report = analyzer.get_memory_report()\n        print("\n" + report)\n\n    elif args.command == 'detect':\n        print("🔍 Detecting memory leaks...")\n\n        # Take multiple snapshots\n        for i in range(10):\n            analyzer.capture_snapshot()\n            time.sleep(6)  # 1 minute of monitoring\n\n        leaks = analyzer.detect_memory_leaks()\n\n        if leaks:\n            print(f"\n⚠️  Found {len(leaks)} potential memory leak(s):
")
            for i, leak in enumerate(leaks, 1):
                print(f"Leak #{i} - {leak.severity.upper()}")
                print(f"  Location: {leak.location}")
                print(f"  Growth rate: {leak.growth_rate_mb_per_min:.2f} MB/min")
                print(f"  Size: {leak.size_mb:.2f} MB
")
        else:
            print("\n✅ No memory leaks detected")\n\n    elif args.command == 'export':\n        metrics = analyzer.export_metrics(\n            output_file=Path(args.output) if args.output else None,\n            format=args.format\n        )\n\n        if not args.output:\n            if args.format == 'json':\n                print(json.dumps(metrics, indent=2))\n            else:\n                print(metrics)\n        else:\n            print(f"✅ Metrics exported to: {args.output}")\n\n    else:\n        parser.print_help()\n\n\nif __name__ == "__main__":\n    main()