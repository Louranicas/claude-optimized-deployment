"""
Document Processing Benchmarking Framework

SYNTHEX Agent 5 Performance Optimization - Benchmarking Suite
Comprehensive performance testing with targets and validation
"""

import asyncio
import json
import time
import tempfile
import shutil
import statistics
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional, Tuple, Callable
import random
import string
import psutil
import gc
from datetime import datetime
import matplotlib.pyplot as plt
import pandas as pd

from .document_processor import (
    DocumentProcessor, ParallelDocumentProcessor, create_optimized_processor,
    DocumentProcessingMetrics, DocumentCache
)

__all__ = [
    "BenchmarkConfig",
    "BenchmarkResult", 
    "PerformanceTarget",
    "DocumentBenchmarkSuite",
    "MemoryProfiler",
    "run_comprehensive_benchmarks"
]


@dataclass
class BenchmarkConfig:
    """Configuration for benchmark tests"""
    name: str
    description: str
    document_sizes_mb: List[int] = None
    document_counts: List[int] = None
    worker_counts: List[int] = None
    cache_sizes: List[int] = None
    iterations: int = 3
    warmup_iterations: int = 1
    enable_profiling: bool = True
    output_dir: Optional[Path] = None
    
    def __post_init__(self):
        if self.document_sizes_mb is None:
            self.document_sizes_mb = [1, 5, 10, 25, 50]
        if self.document_counts is None:
            self.document_counts = [1, 5, 10, 25, 50]
        if self.worker_counts is None:
            self.worker_counts = [1, 2, 4, 8]
        if self.cache_sizes is None:
            self.cache_sizes = [10, 50, 100, 200]
        if self.output_dir is None:
            self.output_dir = Path.cwd() / "benchmark_results"


@dataclass 
class BenchmarkResult:
    """Results from a benchmark test"""
    config_name: str
    test_name: str
    timestamp: datetime
    duration_ms: float
    throughput_mbps: float
    memory_peak_mb: float
    memory_avg_mb: float
    cpu_avg_percent: float
    cache_hit_rate: float
    documents_processed: int
    total_size_mb: float
    error_count: int
    parameters: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result


@dataclass
class PerformanceTarget:
    """Performance targets for validation"""
    min_throughput_mbps: float = 10.0
    max_latency_ms: float = 1000.0
    max_memory_mb: float = 512.0
    min_cache_hit_rate: float = 0.8
    max_error_rate: float = 0.01
    
    def validate(self, result: BenchmarkResult) -> Tuple[bool, List[str]]:
        """Validate benchmark result against targets"""
        issues = []
        
        if result.throughput_mbps < self.min_throughput_mbps:
            issues.append(f"Throughput {result.throughput_mbps:.2f} MB/s below target {self.min_throughput_mbps}")
        
        if result.duration_ms > self.max_latency_ms:
            issues.append(f"Latency {result.duration_ms:.0f}ms above target {self.max_latency_ms}ms")
        
        if result.memory_peak_mb > self.max_memory_mb:
            issues.append(f"Memory {result.memory_peak_mb:.0f}MB above target {self.max_memory_mb}MB")
        
        if result.cache_hit_rate < self.min_cache_hit_rate:
            issues.append(f"Cache hit rate {result.cache_hit_rate:.2%} below target {self.min_cache_hit_rate:.2%}")
        
        error_rate = result.error_count / result.documents_processed if result.documents_processed > 0 else 1
        if error_rate > self.max_error_rate:
            issues.append(f"Error rate {error_rate:.2%} above target {self.max_error_rate:.2%}")
        
        return len(issues) == 0, issues


class MemoryProfiler:
    """Memory usage profiler for benchmarks"""
    
    def __init__(self, sample_interval: float = 0.1):
        self.sample_interval = sample_interval
        self.samples: List[float] = []
        self._monitoring = False
        self._task: Optional[asyncio.Task] = None
    
    async def start(self):
        """Start memory monitoring"""
        if self._monitoring:
            return
        
        self._monitoring = True
        self.samples.clear()
        self._task = asyncio.create_task(self._monitor())
    
    async def stop(self) -> Tuple[float, float]:
        """Stop monitoring and return peak/average memory"""
        if not self._monitoring:
            return 0, 0
        
        self._monitoring = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        if not self.samples:
            return 0, 0
        
        return max(self.samples), statistics.mean(self.samples)
    
    async def _monitor(self):
        """Monitor memory usage"""
        while self._monitoring:
            try:
                memory_mb = psutil.Process().memory_info().rss / 1024 / 1024
                self.samples.append(memory_mb)
                await asyncio.sleep(self.sample_interval)
            except asyncio.CancelledError:
                break
            except Exception:
                pass


class DocumentGenerator:
    """Generate test documents for benchmarks"""
    
    @staticmethod
    def generate_text_content(size_mb: int, structure: str = "chapters") -> str:
        """Generate structured text content"""
        target_chars = size_mb * 1024 * 1024
        content = []
        chars_written = 0
        
        if structure == "chapters":
            chapter_size = target_chars // 10  # ~10 chapters
            for i in range(10):
                content.append(f"\n# Chapter {i + 1}: {DocumentGenerator._random_title()}
")
                
                # Generate chapter content
                while len(content[-1]) < chapter_size:
                    paragraph = DocumentGenerator._random_paragraph()
                    content.append(paragraph + "

")
                
                chars_written += len(content[-1])
                if chars_written >= target_chars:
                    break
        
        elif structure == "sections":
            section_size = target_chars // 20  # ~20 sections
            for i in range(20):
                content.append(f"\n## Section {i + 1}: {DocumentGenerator._random_title()}
")
                
                while len(content[-1]) < section_size:
                    content.append(DocumentGenerator._random_paragraph() + "

")
                
                chars_written += len(''.join(content))
                if chars_written >= target_chars:
                    break
        
        else:  # plain text
            while chars_written < target_chars:
                paragraph = DocumentGenerator._random_paragraph()
                content.append(paragraph + "

")
                chars_written += len(paragraph) + 2
        
        return ''.join(content)[:target_chars]  # Trim to exact size
    
    @staticmethod
    def _random_title() -> str:
        """Generate random title"""
        words = ["Performance", "Optimization", "Processing", "Analysis", 
                "Implementation", "Framework", "System", "Architecture",
                "Design", "Strategy", "Development", "Integration"]
        return ' '.join(random.choices(words, k=random.randint(2, 4)))
    
    @staticmethod
    def _random_paragraph() -> str:
        """Generate random paragraph"""
        sentences = []
        for _ in range(random.randint(3, 8)):
            words = [
                "The", "system", "provides", "comprehensive", "performance",
                "optimization", "through", "advanced", "caching", "strategies",
                "and", "parallel", "processing", "capabilities", "that",
                "enable", "efficient", "document", "handling", "with",
                "minimal", "memory", "overhead", "while", "maintaining",
                "high", "throughput", "and", "reliability", "across",
                "various", "workloads"
            ]
            sentence = ' '.join(random.choices(words, k=random.randint(8, 20)))
            sentences.append(sentence.capitalize() + ".")
        
        return ' '.join(sentences)
    
    @staticmethod
    async def create_test_documents(
        directory: Path,
        sizes_mb: List[int],
        count_per_size: int = 1
    ) -> List[Path]:
        """Create test documents"""
        directory.mkdir(parents=True, exist_ok=True)
        documents = []
        
        for size_mb in sizes_mb:
            for i in range(count_per_size):
                filename = f"test_{size_mb}mb_{i:03d}.md"
                filepath = directory / filename
                
                content = DocumentGenerator.generate_text_content(size_mb)
                filepath.write_text(content, encoding='utf-8')
                documents.append(filepath)
        
        return documents


class DocumentBenchmarkSuite:
    """Comprehensive document processing benchmark suite"""
    
    def __init__(self, config: BenchmarkConfig):
        self.config = config
        self.results: List[BenchmarkResult] = []
        self.test_data_dir: Optional[Path] = None
        self.profiler = MemoryProfiler()
        
        # Performance targets
        self.targets = {
            "small_files": PerformanceTarget(
                min_throughput_mbps=20.0,
                max_latency_ms=500.0,
                max_memory_mb=256.0
            ),
            "large_files": PerformanceTarget(
                min_throughput_mbps=50.0,
                max_latency_ms=2000.0,
                max_memory_mb=1024.0
            ),
            "parallel_processing": PerformanceTarget(
                min_throughput_mbps=100.0,
                max_latency_ms=5000.0,
                max_memory_mb=2048.0
            ),
            "cache_performance": PerformanceTarget(
                min_cache_hit_rate=0.9,
                max_latency_ms=100.0
            )
        }
    
    async def setup(self):
        """Setup benchmark environment"""
        # Create test data directory
        self.test_data_dir = Path(tempfile.mkdtemp(prefix="doc_bench_"))
        
        # Ensure output directory exists
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"Benchmark setup complete:")
        print(f"  Test data: {self.test_data_dir}")
        print(f"  Output: {self.config.output_dir}")
    
    async def teardown(self):
        """Clean up benchmark environment"""
        if self.test_data_dir and self.test_data_dir.exists():
            shutil.rmtree(self.test_data_dir)
    
    async def run_all_benchmarks(self) -> List[BenchmarkResult]:
        """Run all benchmark tests"""
        await self.setup()
        
        try:
            # Single document processing benchmarks
            await self.benchmark_single_document_processing()
            
            # Parallel processing benchmarks
            await self.benchmark_parallel_processing()
            
            # Cache performance benchmarks
            await self.benchmark_cache_performance()
            
            # Memory efficiency benchmarks
            await self.benchmark_memory_efficiency()
            
            # Scaling benchmarks
            await self.benchmark_scaling()
            
            # Generate reports
            await self.generate_reports()
            
        finally:
            await self.teardown()
        
        return self.results
    
    async def benchmark_single_document_processing(self):
        """Benchmark single document processing performance"""
        print("\n=== Single Document Processing Benchmarks ===")\n\n        for size_mb in self.config.document_sizes_mb:\n            print(f"\nTesting {size_mb}MB documents...")\n\n            # Create test document\n            docs = await DocumentGenerator.create_test_documents(\n                self.test_data_dir / "single",\n                [size_mb],\n                count_per_size=1\n            )\n\n            processor, _ = create_optimized_processor(cache_size=100)\n\n            # Warmup\n            for _ in range(self.config.warmup_iterations):\n                await processor.process_document(docs[0])\n\n            # Clear cache for fair testing\n            await processor.clear_cache()\n\n            # Benchmark iterations\n            times = []\n            for iteration in range(self.config.iterations):\n                await self.profiler.start()\n                start_cpu = psutil.cpu_percent()\n\n                start_time = time.time()\n                doc = await processor.process_document(docs[0])\n                duration_ms = (time.time() - start_time) * 1000\n\n                peak_memory, avg_memory = await self.profiler.stop()\n                end_cpu = psutil.cpu_percent()\n\n                times.append(duration_ms)\n\n                metrics = processor.get_metrics()\n\n                result = BenchmarkResult(\n                    config_name=self.config.name,\n                    test_name=f"single_document_{size_mb}mb",\n                    timestamp=datetime.now(),\n                    duration_ms=duration_ms,\n                    throughput_mbps=size_mb / (duration_ms / 1000) if duration_ms > 0 else 0,\n                    memory_peak_mb=peak_memory,\n                    memory_avg_mb=avg_memory,\n                    cpu_avg_percent=(start_cpu + end_cpu) / 2,\n                    cache_hit_rate=metrics.cache_hit_rate,\n                    documents_processed=1,\n                    total_size_mb=size_mb,\n                    error_count=0,\n                    parameters={"size_mb": size_mb, "iteration": iteration}\n                )\n\n                self.results.append(result)\n\n                # Clear cache between iterations\n                await processor.clear_cache()\n\n            avg_time = statistics.mean(times)\n            std_time = statistics.stdev(times) if len(times) > 1 else 0\n            throughput = size_mb / (avg_time / 1000)\n\n            print(f"  Average: {avg_time:.2f}ms ± {std_time:.2f}ms")\n            print(f"  Throughput: {throughput:.2f} MB/s")\n            print(f"  Memory: {peak_memory:.2f}MB peak")\n\n    async def benchmark_parallel_processing(self):\n        """Benchmark parallel document processing"""\n        print("\n=== Parallel Processing Benchmarks ===")\n\n        for worker_count in self.config.worker_counts:\n            for doc_count in [5, 10, 20]:\n                print(f"\nTesting {worker_count} workers with {doc_count} documents...")\n\n                # Create test documents (mix of sizes)\n                sizes = random.choices(self.config.document_sizes_mb[:3], k=doc_count)\n                docs = []\n                for i, size in enumerate(sizes):\n                    doc_list = await DocumentGenerator.create_test_documents(\n                        self.test_data_dir / f"parallel_{worker_count}_{doc_count}",\n                        [size],\n                        count_per_size=1\n                    )\n                    docs.extend(doc_list)\n\n                processor, parallel_processor = create_optimized_processor(\n                    max_workers=worker_count\n                )\n\n                # Warmup\n                for _ in range(self.config.warmup_iterations):\n                    await parallel_processor.process_documents(docs[:2])\n\n                await processor.clear_cache()\n\n                # Benchmark\n                await self.profiler.start()\n                start_cpu = psutil.cpu_percent(interval=None)\n\n                start_time = time.time()\n                results = await parallel_processor.process_documents(docs)\n                duration_ms = (time.time() - start_time) * 1000\n\n                peak_memory, avg_memory = await self.profiler.stop()\n                end_cpu = psutil.cpu_percent(interval=None)\n\n                total_size_mb = sum(sizes)\n                successful_docs = len([r for r in results.values() if r])\n\n                metrics = processor.get_metrics()\n\n                result = BenchmarkResult(\n                    config_name=self.config.name,\n                    test_name=f"parallel_{worker_count}workers_{doc_count}docs",\n                    timestamp=datetime.now(),\n                    duration_ms=duration_ms,\n                    throughput_mbps=total_size_mb / (duration_ms / 1000) if duration_ms > 0 else 0,\n                    memory_peak_mb=peak_memory,\n                    memory_avg_mb=avg_memory,\n                    cpu_avg_percent=(start_cpu + end_cpu) / 2,\n                    cache_hit_rate=metrics.cache_hit_rate,\n                    documents_processed=successful_docs,\n                    total_size_mb=total_size_mb,\n                    error_count=doc_count - successful_docs,\n                    parameters={\n                        "worker_count": worker_count,\n                        "document_count": doc_count,\n                        "document_sizes": sizes\n                    }\n                )\n\n                self.results.append(result)\n\n                throughput = total_size_mb / (duration_ms / 1000)\n                print(f"  Duration: {duration_ms:.2f}ms")\n                print(f"  Throughput: {throughput:.2f} MB/s")\n                print(f"  Efficiency: {throughput/worker_count:.2f} MB/s per worker")\n                print(f"  Success rate: {successful_docs/doc_count:.2%}")\n\n    async def benchmark_cache_performance(self):\n        """Benchmark caching effectiveness"""\n        print("\n=== Cache Performance Benchmarks ===")\n\n        for cache_size in self.config.cache_sizes:\n            print(f"\nTesting cache size: {cache_size}")\n\n            # Create test documents\n            docs = await DocumentGenerator.create_test_documents(\n                self.test_data_dir / f"cache_{cache_size}",\n                [5],  # 5MB documents\n                count_per_size=cache_size + 10  # More docs than cache size\n            )\n\n            processor, _ = create_optimized_processor(cache_size=cache_size)\n\n            # First pass - populate cache\n            print("  Populating cache...")\n            for doc in docs[:cache_size]:\n                await processor.process_document(doc)\n\n            # Second pass - test cache hits\n            print("  Testing cache hits...")\n            await self.profiler.start()\n\n            start_time = time.time()\n            hit_count = 0\n\n            for doc in docs[:cache_size]:\n                result_doc = await processor.process_document(doc)\n                if result_doc.cached:\n                    hit_count += 1\n\n            duration_ms = (time.time() - start_time) * 1000\n            peak_memory, avg_memory = await self.profiler.stop()\n\n            metrics = processor.get_metrics()\n\n            result = BenchmarkResult(\n                config_name=self.config.name,\n                test_name=f"cache_performance_{cache_size}",\n                timestamp=datetime.now(),\n                duration_ms=duration_ms,\n                throughput_mbps=(cache_size * 5) / (duration_ms / 1000) if duration_ms > 0 else 0,\n                memory_peak_mb=peak_memory,\n                memory_avg_mb=avg_memory,\n                cpu_avg_percent=0,  # Cached access should use minimal CPU\n                cache_hit_rate=hit_count / cache_size,\n                documents_processed=cache_size,\n                total_size_mb=cache_size * 5,\n                error_count=0,\n                parameters={"cache_size": cache_size}\n            )\n\n            self.results.append(result)\n\n            print(f"  Cache hit rate: {hit_count/cache_size:.2%}")\n            print(f"  Average access time: {duration_ms/cache_size:.2f}ms")\n\n    async def benchmark_memory_efficiency(self):\n        """Benchmark memory usage patterns"""\n        print("\n=== Memory Efficiency Benchmarks ===")\n\n        # Test memory usage with increasing document sizes\n        for size_mb in [10, 25, 50, 100]:\n            print(f"\nTesting memory efficiency with {size_mb}MB document...")\n\n            docs = await DocumentGenerator.create_test_documents(\n                self.test_data_dir / "memory",\n                [size_mb],\n                count_per_size=1\n            )\n\n            processor, _ = create_optimized_processor()\n\n            # Force garbage collection before test\n            gc.collect()\n            initial_memory = psutil.Process().memory_info().rss / 1024 / 1024\n\n            await self.profiler.start()\n\n            doc = await processor.process_document(docs[0])\n\n            peak_memory, avg_memory = await self.profiler.stop()\n\n            # Force GC and measure final memory\n            del doc\n            gc.collect()\n            final_memory = psutil.Process().memory_info().rss / 1024 / 1024\n\n            memory_overhead = peak_memory - initial_memory\n            memory_retention = final_memory - initial_memory\n\n            result = BenchmarkResult(\n                config_name=self.config.name,\n                test_name=f"memory_efficiency_{size_mb}mb",\n                timestamp=datetime.now(),\n                duration_ms=0,\n                throughput_mbps=0,\n                memory_peak_mb=peak_memory,\n                memory_avg_mb=avg_memory,\n                cpu_avg_percent=0,\n                cache_hit_rate=0,\n                documents_processed=1,\n                total_size_mb=size_mb,\n                error_count=0,\n                parameters={\n                    "size_mb": size_mb,\n                    "memory_overhead_mb": memory_overhead,\n                    "memory_retention_mb": memory_retention,\n                    "memory_efficiency": size_mb / memory_overhead if memory_overhead > 0 else 0\n                }\n            )\n\n            self.results.append(result)\n\n            print(f"  Peak memory: {peak_memory:.2f}MB")\n            print(f"  Memory overhead: {memory_overhead:.2f}MB")\n            print(f"  Memory efficiency: {size_mb/memory_overhead:.2f}x" if memory_overhead > 0 else "  Perfect efficiency")\n\n    async def benchmark_scaling(self):\n        """Benchmark scaling characteristics"""\n        print("\n=== Scaling Benchmarks ===")\n\n        # Test how performance scales with document count\n        base_count = 5\n        for multiplier in [1, 2, 4, 8]:\n            doc_count = base_count * multiplier\n            print(f"\nTesting scaling with {doc_count} documents...")\n\n            docs = await DocumentGenerator.create_test_documents(\n                self.test_data_dir / f"scaling_{doc_count}",\n                [5],  # 5MB each\n                count_per_size=doc_count\n            )\n\n            processor, parallel_processor = create_optimized_processor()\n\n            await self.profiler.start()\n\n            start_time = time.time()\n            results = await parallel_processor.process_documents(docs)\n            duration_ms = (time.time() - start_time) * 1000\n\n            peak_memory, avg_memory = await self.profiler.stop()\n\n            successful = len([r for r in results.values() if r])\n            total_size_mb = successful * 5\n\n            result = BenchmarkResult(\n                config_name=self.config.name,\n                test_name=f"scaling_{doc_count}docs",\n                timestamp=datetime.now(),\n                duration_ms=duration_ms,\n                throughput_mbps=total_size_mb / (duration_ms / 1000) if duration_ms > 0 else 0,\n                memory_peak_mb=peak_memory,\n                memory_avg_mb=avg_memory,\n                cpu_avg_percent=0,\n                cache_hit_rate=0,\n                documents_processed=successful,\n                total_size_mb=total_size_mb,\n                error_count=doc_count - successful,\n                parameters={\n                    "document_count": doc_count,\n                    "multiplier": multiplier,\n                    "scaling_efficiency": (total_size_mb / (duration_ms / 1000)) / doc_count if duration_ms > 0 else 0\n                }\n            )\n\n            self.results.append(result)\n\n            efficiency = (total_size_mb / (duration_ms / 1000)) / doc_count if duration_ms > 0 else 0\n            print(f"  Throughput: {total_size_mb / (duration_ms / 1000):.2f} MB/s")\n            print(f"  Per-document efficiency: {efficiency:.2f} MB/s")\n\n    async def generate_reports(self):\n        """Generate benchmark reports"""\n        print("\n=== Generating Reports ===")\n\n        # Save raw results\n        results_file = self.config.output_dir / f"benchmark_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"\n        with open(results_file, 'w') as f:\n            json.dump([r.to_dict() for r in self.results], f, indent=2)\n\n        print(f"Raw results saved to: {results_file}")\n\n        # Generate summary report\n        await self._generate_summary_report()\n\n        # Generate performance validation report\n        await self._generate_validation_report()\n\n        # Generate visualizations\n        if len(self.results) > 0:\n            await self._generate_visualizations()\n\n    async def _generate_summary_report(self):\n        """Generate summary report"""\n        report_file = self.config.output_dir / "benchmark_summary.md"\n\n        with open(report_file, 'w') as f:\n            f.write(f"# Document Processing Benchmark Report\n
")
            f.write(f"**Configuration:** {self.config.name}
")
            f.write(f"**Generated:** {datetime.now().isoformat()}
")
            f.write(f"**Total Tests:** {len(self.results)}

")
            
            # Group results by test type
            test_groups = {}
            for result in self.results:
                test_type = result.test_name.split('_')[0]
                if test_type not in test_groups:
                    test_groups[test_type] = []
                test_groups[test_type].append(result)
            
            for test_type, results in test_groups.items():
                f.write(f"## {test_type.title()} Results

")
                
                avg_throughput = statistics.mean([r.throughput_mbps for r in results])
                avg_memory = statistics.mean([r.memory_peak_mb for r in results])
                
                f.write(f"- **Average Throughput:** {avg_throughput:.2f} MB/s
")
                f.write(f"- **Average Peak Memory:** {avg_memory:.2f} MB
")
                f.write(f"- **Test Count:** {len(results)}

")
                
                # Top performers
                top_throughput = max(results, key=lambda x: x.throughput_mbps)
                f.write(f"**Best Throughput:** {top_throughput.throughput_mbps:.2f} MB/s ")
                f.write(f"({top_throughput.test_name})

")
        
        print(f"Summary report saved to: {report_file}")
    
    async def _generate_validation_report(self):
        """Generate performance validation report"""
        report_file = self.config.output_dir / "validation_report.md"
        
        with open(report_file, 'w') as f:
            f.write(f"# Performance Validation Report

")
            
            total_tests = len(self.results)
            passed_tests = 0
            
            for result in self.results:
                # Determine target category
                target_key = "small_files"
                if result.total_size_mb > 20:
                    target_key = "large_files"
                elif "parallel" in result.test_name:
                    target_key = "parallel_processing"
                elif "cache" in result.test_name:
                    target_key = "cache_performance"
                
                target = self.targets[target_key]
                is_valid, issues = target.validate(result)
                
                if is_valid:
                    passed_tests += 1
                    f.write(f"✅ **{result.test_name}** - PASSED
")
                else:
                    f.write(f"❌ **{result.test_name}** - FAILED
")
                    for issue in issues:
                        f.write(f"   - {issue}
")
                f.write("
")
            
            pass_rate = passed_tests / total_tests if total_tests > 0 else 0
            f.write(f"## Summary

")
            f.write(f"- **Total Tests:** {total_tests}
")
            f.write(f"- **Passed:** {passed_tests}
")
            f.write(f"- **Failed:** {total_tests - passed_tests}
")
            f.write(f"- **Pass Rate:** {pass_rate:.2%}
")
        
        print(f"Validation report saved to: {report_file}")
    
    async def _generate_visualizations(self):
        """Generate performance visualization charts"""
        try:
            # Create DataFrame
            df = pd.DataFrame([r.to_dict() for r in self.results])
            
            # Throughput vs Document Size
            plt.figure(figsize=(12, 8))
            
            plt.subplot(2, 2, 1)
            single_doc_results = df[df['test_name'].str.contains('single')]
            if not single_doc_results.empty:
                sizes = [r['parameters']['size_mb'] for _, r in single_doc_results.iterrows()]
                throughputs = single_doc_results['throughput_mbps'].tolist()
                plt.plot(sizes, throughputs, 'o-')
                plt.xlabel('Document Size (MB)')
                plt.ylabel('Throughput (MB/s)')
                plt.title('Single Document Processing')
                plt.grid(True)
            
            # Memory Usage
            plt.subplot(2, 2, 2)
            plt.scatter(df['total_size_mb'], df['memory_peak_mb'], alpha=0.6)
            plt.xlabel('Total Data Size (MB)')
            plt.ylabel('Peak Memory (MB)')
            plt.title('Memory Usage')
            plt.grid(True)
            
            # Parallel Processing Efficiency
            plt.subplot(2, 2, 3)
            parallel_results = df[df['test_name'].str.contains('parallel')]
            if not parallel_results.empty:
                worker_counts = [r['parameters']['worker_count'] for _, r in parallel_results.iterrows()]
                throughputs = parallel_results['throughput_mbps'].tolist()
                plt.scatter(worker_counts, throughputs, alpha=0.6)
                plt.xlabel('Worker Count')
                plt.ylabel('Throughput (MB/s)')
                plt.title('Parallel Processing Scaling')
                plt.grid(True)
            
            # Cache Performance
            plt.subplot(2, 2, 4)
            cache_results = df[df['test_name'].str.contains('cache')]
            if not cache_results.empty:
                cache_sizes = [r['parameters']['cache_size'] for _, r in cache_results.iterrows()]
                hit_rates = cache_results['cache_hit_rate'].tolist()
                plt.plot(cache_sizes, hit_rates, 'o-')
                plt.xlabel('Cache Size')
                plt.ylabel('Hit Rate')
                plt.title('Cache Performance')
                plt.grid(True)
            
            plt.tight_layout()
            chart_file = self.config.output_dir / "performance_charts.png"
            plt.savefig(chart_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            print(f"Charts saved to: {chart_file}")
            
        except ImportError:
            print("Matplotlib/Pandas not available, skipping visualizations")
        except Exception as e:
            print(f"Error generating visualizations: {e}")


async def run_comprehensive_benchmarks() -> List[BenchmarkResult]:
    """
    Run comprehensive document processing benchmarks
    
    Returns:
        List of benchmark results
    """
    # Define benchmark configurations
    configs = [
        BenchmarkConfig(
            name="quick_performance_test",
            description="Quick performance validation",
            document_sizes_mb=[1, 5, 10],
            document_counts=[1, 5, 10],
            worker_counts=[1, 2, 4],
            cache_sizes=[10, 50],
            iterations=2
        ),
        BenchmarkConfig(
            name="comprehensive_performance_test",
            description="Comprehensive performance benchmarking",
            document_sizes_mb=[1, 5, 10, 25, 50],
            document_counts=[1, 5, 10, 25, 50],
            worker_counts=[1, 2, 4, 8],
            cache_sizes=[10, 50, 100, 200],
            iterations=3
        )
    ]
    
    all_results = []
    
    for config in configs:
        print(f"\n{'='*60}")\n        print(f"Running benchmark configuration: {config.name}")\n        print(f"Description: {config.description}")\n        print(f"{'='*60}")\n\n        suite = DocumentBenchmarkSuite(config)\n        results = await suite.run_all_benchmarks()\n        all_results.extend(results)\n\n        print(f"\nCompleted {len(results)} benchmark tests")\n\n    print(f"\n{'='*60}")\n    print(f"BENCHMARK SUMMARY")\n    print(f"Total tests completed: {len(all_results)}")\n\n    if all_results:\n        avg_throughput = statistics.mean([r.throughput_mbps for r in all_results])\n        max_throughput = max([r.throughput_mbps for r in all_results])\n        avg_memory = statistics.mean([r.memory_peak_mb for r in all_results])\n\n        print(f"Average throughput: {avg_throughput:.2f} MB/s")\n        print(f"Maximum throughput: {max_throughput:.2f} MB/s")\n        print(f"Average memory usage: {avg_memory:.2f} MB")\n\n    print(f"{'='*60}")\n\n    return all_results\n\n\n# Example usage\nif __name__ == "__main__":\n    # Run benchmarks\n    results = asyncio.run(run_comprehensive_benchmarks())\n\n    print(f"\nBenchmarking complete! Generated {len(results)} results.")\n    print("Check the 'benchmark_results' directory for detailed reports.")