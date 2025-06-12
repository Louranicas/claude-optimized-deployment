"""
Advanced Memory Profiler
Detailed memory profiling and analysis tools.
"""

import gc
import time
import tracemalloc
import psutil
import threading
import weakref
import sys
import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import statistics
from collections import defaultdict, Counter
import linecache
import pickle


@dataclass
class AllocationEntry:
    """Individual memory allocation entry"""
    size: int
    filename: str
    lineno: int
    traceback: List[str]
    timestamp: float
    object_type: str


@dataclass
class MemoryProfile:
    """Complete memory profile result"""
    component_name: str
    start_time: float
    end_time: float
    duration: float
    peak_memory_mb: float
    total_allocations: int
    total_deallocations: int
    net_allocations: int
    top_allocations: List[AllocationEntry]
    allocation_by_file: Dict[str, int]
    allocation_by_type: Dict[str, int]
    memory_timeline: List[Tuple[float, float]]  # (timestamp, memory_mb)
    gc_events: List[Dict[str, Any]]
    recommendations: List[str]


class AdvancedMemoryProfiler:
    """Advanced memory profiling with detailed analysis"""
    
    def __init__(self, max_traceback_depth: int = 10):
        self.max_traceback_depth = max_traceback_depth
        self.allocations: List[AllocationEntry] = []
        self.gc_events: List[Dict[str, Any]] = []
        self.memory_timeline: List[Tuple[float, float]] = []
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.component_name: str = "unknown"
        self.monitoring_thread: Optional[threading.Thread] = None
        self.stop_monitoring = threading.Event()
        self.process = psutil.Process()
        
    def start_profiling(self, component_name: str = "unknown"):
        """Start memory profiling"""
        self.component_name = component_name
        self.start_time = time.time()
        self.allocations.clear()
        self.gc_events.clear()
        self.memory_timeline.clear()
        self.stop_monitoring.clear()
        
        # Start tracemalloc with maximum detail
        tracemalloc.start(self.max_traceback_depth)
        
        # Start continuous monitoring
        self.monitoring_thread = threading.Thread(
            target=self._continuous_monitoring,
            daemon=True
        )
        self.monitoring_thread.start()
        
        # Force initial GC and take snapshot
        gc.collect()
        self._record_memory_point("start")
        
        print(f"Started memory profiling for {component_name}")
    
    def stop_profiling(self) -> MemoryProfile:
        """Stop profiling and return analysis"""
        if not self.start_time:
            raise RuntimeError("Profiling not started")
        
        self.end_time = time.time()
        
        # Stop monitoring
        self.stop_monitoring.set()
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5.0)
        
        # Final memory snapshot
        gc.collect()
        self._record_memory_point("end")
        
        # Get final tracemalloc snapshot
        if tracemalloc.is_tracing():
            snapshot = tracemalloc.take_snapshot()
            self._process_tracemalloc_snapshot(snapshot)
            tracemalloc.stop()
        
        # Generate profile
        profile = self._generate_profile()
        
        print(f"Completed memory profiling for {self.component_name}")
        return profile
    
    def _continuous_monitoring(self):
        """Continuous memory monitoring loop"""
        while not self.stop_monitoring.wait(0.1):  # Monitor every 100ms
            self._record_memory_point("monitoring")
            
            # Check for GC events
            gc_counts = gc.get_count()
            if hasattr(self, '_last_gc_counts'):
                gc_deltas = [
                    gc_counts[i] - self._last_gc_counts[i] 
                    for i in range(len(gc_counts))
                ]
                if any(delta > 0 for delta in gc_deltas):
                    self.gc_events.append({
                        'timestamp': time.time(),
                        'gc_counts': gc_counts,
                        'gc_deltas': gc_deltas
                    })
            self._last_gc_counts = gc_counts
    
    def _record_memory_point(self, description: str):
        """Record a memory usage point"""
        memory_info = self.process.memory_info()
        memory_mb = memory_info.rss / 1024 / 1024
        timestamp = time.time()
        
        self.memory_timeline.append((timestamp, memory_mb))
    
    def _process_tracemalloc_snapshot(self, snapshot):
        """Process tracemalloc snapshot for allocations"""
        for stat in snapshot.statistics('traceback'):
            # Get traceback information
            traceback_lines = []
            for frame in stat.traceback:
                line = linecache.getline(frame.filename, frame.lineno).strip()
                traceback_lines.append(f"{frame.filename}:{frame.lineno}: {line}")
            
            # Determine object type from traceback
            object_type = self._infer_object_type(stat.traceback, traceback_lines)
            
            allocation = AllocationEntry(
                size=stat.size,
                filename=stat.traceback[0].filename if stat.traceback else "unknown",
                lineno=stat.traceback[0].lineno if stat.traceback else 0,
                traceback=traceback_lines,
                timestamp=time.time(),
                object_type=object_type
            )
            
            self.allocations.append(allocation)
    
    def _infer_object_type(self, traceback, traceback_lines: List[str]) -> str:
        """Infer object type from traceback"""
        # Look for common patterns in traceback
        for line in traceback_lines:
            if 'list(' in line or '.append(' in line:
                return 'list'
            elif 'dict(' in line or 'defaultdict' in line:
                return 'dict'
            elif 'str(' in line or "'" in line or '"' in line:
                return 'str'
            elif 'ExpertResponse' in line:
                return 'ExpertResponse'
            elif 'ExpertQuery' in line:
                return 'ExpertQuery'
            elif 'DataFrame' in line:
                return 'DataFrame'
        
        return 'unknown'
    
    def _generate_profile(self) -> MemoryProfile:
        """Generate comprehensive memory profile"""
        duration = self.end_time - self.start_time
        
        # Calculate peak memory
        peak_memory_mb = max(memory for _, memory in self.memory_timeline) if self.memory_timeline else 0
        
        # Analyze allocations
        allocation_by_file = defaultdict(int)
        allocation_by_type = defaultdict(int)
        
        for alloc in self.allocations:
            allocation_by_file[os.path.basename(alloc.filename)] += alloc.size
            allocation_by_type[alloc.object_type] += alloc.size
        
        # Get top allocations
        top_allocations = sorted(self.allocations, key=lambda x: x.size, reverse=True)[:20]
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            peak_memory_mb, allocation_by_type, allocation_by_file
        )
        
        return MemoryProfile(
            component_name=self.component_name,
            start_time=self.start_time,
            end_time=self.end_time,
            duration=duration,
            peak_memory_mb=peak_memory_mb,
            total_allocations=len(self.allocations),
            total_deallocations=0,  # Not tracked in current implementation
            net_allocations=len(self.allocations),
            top_allocations=top_allocations,
            allocation_by_file=dict(allocation_by_file),
            allocation_by_type=dict(allocation_by_type),
            memory_timeline=self.memory_timeline,
            gc_events=self.gc_events,
            recommendations=recommendations
        )
    
    def _generate_recommendations(
        self, 
        peak_memory_mb: float,
        allocation_by_type: Dict[str, int],
        allocation_by_file: Dict[str, int]
    ) -> List[str]:
        """Generate optimization recommendations"""
        recommendations = []
        
        # Memory usage recommendations
        if peak_memory_mb > 500:
            recommendations.append(f"High peak memory usage ({peak_memory_mb:.1f}MB) - consider optimizing data structures")
        
        # Type-specific recommendations
        total_allocations = sum(allocation_by_type.values())
        if total_allocations > 0:
            for obj_type, size in allocation_by_type.items():
                percentage = (size / total_allocations) * 100
                if percentage > 30:
                    recommendations.append(f"High {obj_type} allocation ({percentage:.1f}%) - consider object pooling")
        
        # File-specific recommendations
        top_files = sorted(allocation_by_file.items(), key=lambda x: x[1], reverse=True)[:3]
        for filename, size in top_files:
            if size > 1024 * 1024:  # > 1MB
                recommendations.append(f"High allocation in {filename} ({size/1024/1024:.1f}MB) - review allocation patterns")
        
        if not recommendations:
            recommendations.append("Memory usage appears optimized")
        
        return recommendations
    
    def save_profile(self, profile: MemoryProfile, output_dir: str = "profiles"):
        """Save profile to files"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"memory_profile_{profile.component_name}_{timestamp}"
        
        # Save JSON report
        json_path = output_path / f"{base_filename}.json"
        with open(json_path, 'w') as f:
            # Convert profile to JSON-serializable format
            profile_dict = asdict(profile)
            # Handle non-serializable objects
            profile_dict['top_allocations'] = [asdict(alloc) for alloc in profile.top_allocations]
            json.dump(profile_dict, f, indent=2, default=str)
        
        # Save detailed report
        report_path = output_path / f"{base_filename}.md"
        with open(report_path, 'w') as f:
            f.write(self.generate_report(profile))
        
        print(f"Profile saved to {json_path} and {report_path}")
        return json_path, report_path
    
    def generate_report(self, profile: MemoryProfile) -> str:
        """Generate human-readable report"""
        report = []
        report.append(f"# Memory Profile Report: {profile.component_name}")
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append("")
        
        # Summary
        report.append("## Summary")
        report.append(f"- **Duration**: {profile.duration:.2f} seconds")
        report.append(f"- **Peak Memory**: {profile.peak_memory_mb:.2f} MB")
        report.append(f"- **Total Allocations**: {profile.total_allocations:,}")
        report.append(f"- **GC Events**: {len(profile.gc_events)}")
        report.append("")
        
        # Memory timeline
        if profile.memory_timeline:
            initial_memory = profile.memory_timeline[0][1]
            final_memory = profile.memory_timeline[-1][1]
            memory_growth = final_memory - initial_memory
            
            report.append("## Memory Timeline")
            report.append(f"- **Initial Memory**: {initial_memory:.2f} MB")
            report.append(f"- **Final Memory**: {final_memory:.2f} MB")
            report.append(f"- **Memory Growth**: {memory_growth:+.2f} MB")
            report.append(f"- **Peak Memory**: {profile.peak_memory_mb:.2f} MB")
            report.append("")
        
        # Top allocations
        report.append("## Top Memory Allocations")
        for i, alloc in enumerate(profile.top_allocations[:10], 1):
            report.append(f"### {i}. {alloc.object_type} ({alloc.size / 1024:.1f} KB)")
            report.append(f"- **File**: {os.path.basename(alloc.filename)}:{alloc.lineno}")
            report.append(f"- **Size**: {alloc.size:,} bytes")
            if alloc.traceback:
                report.append("- **Traceback**:")
                for line in alloc.traceback[:3]:  # Show top 3 lines
                    report.append(f"  - {line}")
            report.append("")
        
        # Allocation by type
        report.append("## Allocation by Type")
        total_size = sum(profile.allocation_by_type.values())
        for obj_type, size in sorted(profile.allocation_by_type.items(), key=lambda x: x[1], reverse=True):
            percentage = (size / total_size * 100) if total_size > 0 else 0
            report.append(f"- **{obj_type}**: {size / 1024:.1f} KB ({percentage:.1f}%)")
        report.append("")
        
        # Allocation by file
        report.append("## Allocation by File")
        for filename, size in sorted(profile.allocation_by_file.items(), key=lambda x: x[1], reverse=True)[:10]:
            report.append(f"- **{filename}**: {size / 1024:.1f} KB")
        report.append("")
        
        # GC events
        if profile.gc_events:
            report.append("## Garbage Collection Events")
            report.append(f"- **Total GC Events**: {len(profile.gc_events)}")
            
            # Analyze GC frequency
            if len(profile.gc_events) > 1:
                gc_intervals = []
                for i in range(1, len(profile.gc_events)):
                    interval = profile.gc_events[i]['timestamp'] - profile.gc_events[i-1]['timestamp']
                    gc_intervals.append(interval)
                
                avg_interval = statistics.mean(gc_intervals)
                report.append(f"- **Average GC Interval**: {avg_interval:.2f} seconds")
            report.append("")
        
        # Recommendations
        report.append("## Recommendations")
        for rec in profile.recommendations:
            report.append(f"- {rec}")
        report.append("")
        
        return "\n".join(report)


class MemoryComparator:
    """Compare memory profiles across different runs"""
    
    def __init__(self):
        pass
    
    def compare_profiles(self, profile1: MemoryProfile, profile2: MemoryProfile) -> Dict[str, Any]:
        """Compare two memory profiles"""
        comparison = {
            'profile1_name': profile1.component_name,
            'profile2_name': profile2.component_name,
            'peak_memory_delta_mb': profile2.peak_memory_mb - profile1.peak_memory_mb,
            'duration_delta_seconds': profile2.duration - profile1.duration,
            'allocations_delta': profile2.total_allocations - profile1.total_allocations,
            'gc_events_delta': len(profile2.gc_events) - len(profile1.gc_events),
            'type_allocation_changes': {},
            'file_allocation_changes': {},
            'regression_detected': False,
            'improvements_detected': False,
            'recommendations': []
        }
        
        # Compare allocation by type
        all_types = set(profile1.allocation_by_type.keys()) | set(profile2.allocation_by_type.keys())
        for obj_type in all_types:
            size1 = profile1.allocation_by_type.get(obj_type, 0)
            size2 = profile2.allocation_by_type.get(obj_type, 0)
            delta = size2 - size1
            if delta != 0:
                comparison['type_allocation_changes'][obj_type] = delta
        
        # Compare allocation by file
        all_files = set(profile1.allocation_by_file.keys()) | set(profile2.allocation_by_file.keys())
        for filename in all_files:
            size1 = profile1.allocation_by_file.get(filename, 0)
            size2 = profile2.allocation_by_file.get(filename, 0)
            delta = size2 - size1
            if delta != 0:
                comparison['file_allocation_changes'][filename] = delta
        
        # Detect regressions and improvements
        peak_memory_change_percent = (comparison['peak_memory_delta_mb'] / profile1.peak_memory_mb * 100) if profile1.peak_memory_mb > 0 else 0
        
        if peak_memory_change_percent > 15:  # >15% increase
            comparison['regression_detected'] = True
            comparison['recommendations'].append(f"Memory regression detected: {peak_memory_change_percent:.1f}% increase in peak memory")
        elif peak_memory_change_percent < -10:  # >10% decrease
            comparison['improvements_detected'] = True
            comparison['recommendations'].append(f"Memory improvement detected: {abs(peak_memory_change_percent):.1f}% decrease in peak memory")
        
        return comparison


# Profiling decorators
def profile_memory(component_name: str = None, save_profile: bool = True):
    """Decorator for memory profiling"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            profiler = AdvancedMemoryProfiler()
            name = component_name or func.__name__
            
            profiler.start_profiling(name)
            try:
                result = func(*args, **kwargs)
            finally:
                profile = profiler.stop_profiling()
                if save_profile:
                    profiler.save_profile(profile)
            
            return result
        return wrapper
    return decorator


def profile_async_memory(component_name: str = None, save_profile: bool = True):
    """Decorator for async memory profiling"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            profiler = AdvancedMemoryProfiler()
            name = component_name or func.__name__
            
            profiler.start_profiling(name)
            try:
                result = await func(*args, **kwargs)
            finally:
                profile = profiler.stop_profiling()
                if save_profile:
                    profiler.save_profile(profile)
            
            return result
        return wrapper
    return decorator


# Example usage
if __name__ == "__main__":
    # Test memory profiler
    profiler = AdvancedMemoryProfiler()
    
    profiler.start_profiling("test_profiling")
    
    # Simulate some memory operations
    test_data = []
    for i in range(1000):
        data = {
            'id': i,
            'content': 'x' * 1000,  # 1KB per object
            'metadata': {'timestamp': time.time()}
        }
        test_data.append(data)
    
    time.sleep(0.5)
    
    profile = profiler.stop_profiling()
    
    # Generate and save report
    profiler.save_profile(profile)
    
    print("Memory profiling test completed!")