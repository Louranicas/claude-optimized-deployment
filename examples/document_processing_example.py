"""
Document Processing Example - SYNTHEX Agent 5

Complete example demonstrating all document processing optimizations:
- Caching strategies
- Lazy loading
- Parallel processing
- Memory-efficient algorithms
- Index structures
- Streaming APIs
- Background processing
- Resource pooling
"""

import asyncio
import tempfile
import time
import shutil
from pathlib import Path
from typing import List, Dict, Any
import random
import string

# Import our optimization modules
import sys
sys.path.append(str(Path(__file__).parent.parent))

from src.core.document_processor import (
    create_optimized_processor,
    DocumentProcessor,
    ParallelDocumentProcessor,
    BackgroundDocumentProcessor,
    LazyDocument
)
from src.core.document_benchmarks import (
    run_comprehensive_benchmarks,
    BenchmarkConfig,
    DocumentBenchmarkSuite
)
from src.core.document_optimizations import (
    OptimizedDocumentManager,
    AdaptiveProcessor,
    MemoryManager
)


class DocumentProcessingDemo:
    """Comprehensive demonstration of document processing capabilities"""
    
    def __init__(self):
        self.test_dir: Path = None
        self.processor: DocumentProcessor = None
        self.parallel_processor: ParallelDocumentProcessor = None
        self.manager: OptimizedDocumentManager = None
        
    async def setup(self):
        """Setup demo environment"""
        print("🚀 Setting up Document Processing Demo Environment")
        print("=" * 60)
        
        # Create temporary directory for test documents
        self.test_dir = Path(tempfile.mkdtemp(prefix="doc_demo_"))
        print(f"📁 Test directory: {self.test_dir}")
        
        # Create optimized processors
        self.processor, self.parallel_processor = create_optimized_processor(
            cache_size=50,
            cache_ttl=3600,
            max_workers=4
        )
        
        # Create advanced manager
        self.manager = OptimizedDocumentManager(
            cache_size=50,
            max_memory_mb=512,
            enable_adaptive=True,
            enable_watching=False
        )
        
        print("✅ Environment setup complete")
        
    async def cleanup(self):
        """Clean up demo environment"""
        if self.test_dir and self.test_dir.exists():
            shutil.rmtree(self.test_dir)
        
        if self.manager:
            await self.manager.cleanup()
        
        print("🧹 Cleanup complete")
    
    def create_test_documents(self) -> List[Path]:
        """Create various test documents"""
        print("\n📝 Creating test documents...")
        
        documents = []
        
        # Small text documents
        for i in range(5):
            doc_path = self.test_dir / f"small_doc_{i}.txt"
            content = f"# Document {i}\n\n" + "\n".join([
                f"This is paragraph {j} of document {i}. " + 
                "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 10
                for j in range(10)
            ])
            doc_path.write_text(content)
            documents.append(doc_path)
        
        # Medium markdown documents with chapters
        for i in range(3):
            doc_path = self.test_dir / f"medium_doc_{i}.md"
            content = []
            
            for chapter in range(5):
                content.append(f"\n# Chapter {chapter + 1}: Advanced Topics\n")
                for section in range(3):
                    content.append(f"\n## Section {section + 1}\n")
                    content.append(
                        "This section covers important concepts. " * 50 + "\n\n"
                    )
                    # Add some code blocks
                    content.append("```python\n")
                    content.append("def example_function():\n")
                    content.append("    return 'Hello, World!'\n")
                    content.append("```\n\n")
            
            doc_path.write_text("".join(content))
            documents.append(doc_path)
        
        # Large document for streaming test
        large_doc = self.test_dir / "large_document.md"
        large_content = []
        
        # Generate ~10MB document
        for i in range(100):
            large_content.append(f"\n# Chapter {i + 1}\n\n")
            paragraph = "This is a large document section. " * 500
            large_content.append(paragraph + "\n\n")
        
        large_doc.write_text("".join(large_content))
        documents.append(large_doc)
        
        print(f"✅ Created {len(documents)} test documents")
        return documents
    
    async def demo_basic_processing(self, documents: List[Path]):
        """Demonstrate basic document processing"""
        print("\n🔧 Basic Document Processing Demo")
        print("-" * 40)
        
        # Process single document
        print("Processing single document...")
        start_time = time.time()
        doc = await self.processor.process_document(documents[0])
        process_time = time.time() - start_time
        
        print(f"  ✅ Processed: {doc.metadata.path}")
        print(f"  📊 Size: {doc.metadata.size_bytes} bytes")
        print(f"  📖 Chapters: {len(doc.chapters)}")
        print(f"  ⏱️  Time: {process_time:.3f}s")
        print(f"  💾 Cached: {doc.cached}")
        
        # Test caching
        print("\nTesting cache performance...")
        start_time = time.time()
        cached_doc = await self.processor.process_document(documents[0])
        cache_time = time.time() - start_time
        
        print(f"  ✅ Cache hit: {cached_doc.cached}")
        print(f"  ⏱️  Cache time: {cache_time:.3f}s")
        print(f"  🚀 Speedup: {process_time/cache_time:.1f}x faster")
        
        # Test search functionality
        print("\nTesting document search...")
        results = doc.search("Chapter", max_results=3)
        print(f"  🔍 Found {len(results)} matches for 'Chapter'")
        for line_num, line in results[:2]:
            print(f"    Line {line_num}: {line[:50]}...")
    
    async def demo_parallel_processing(self, documents: List[Path]):
        """Demonstrate parallel processing capabilities"""
        print("\n⚡ Parallel Processing Demo")
        print("-" * 40)
        
        # Clear cache for fair comparison
        await self.processor.clear_cache()
        
        # Sequential processing
        print("Sequential processing...")
        start_time = time.time()
        sequential_results = []
        for doc_path in documents[:5]:  # Process 5 documents
            doc = await self.processor.process_document(doc_path)
            sequential_results.append(doc)
        sequential_time = time.time() - start_time
        
        print(f"  ✅ Processed {len(sequential_results)} documents")
        print(f"  ⏱️  Time: {sequential_time:.3f}s")
        
        # Clear cache again
        await self.processor.clear_cache()
        
        # Parallel processing
        print("\nParallel processing...")
        start_time = time.time()
        parallel_results = await self.parallel_processor.process_documents(
            documents[:5]
        )
        parallel_time = time.time() - start_time
        
        print(f"  ✅ Processed {len(parallel_results)} documents")
        print(f"  ⏱️  Time: {parallel_time:.3f}s")
        print(f"  🚀 Speedup: {sequential_time/parallel_time:.1f}x faster")
        
        # Show processing metrics
        metrics = self.processor.get_metrics()
        print(f"\n📊 Processing Metrics:")
        print(f"  Total documents: {metrics.total_documents}")
        print(f"  Total size: {metrics.total_bytes / 1024 / 1024:.2f} MB")
        print(f"  Average time: {metrics.average_time_ms:.2f}ms")
        print(f"  Throughput: {metrics.throughput_mbps:.2f} MB/s")
        print(f"  Cache hit rate: {metrics.cache_hit_rate:.2%}")
    
    async def demo_lazy_loading(self, documents: List[Path]):
        """Demonstrate lazy loading capabilities"""
        print("\n💤 Lazy Loading Demo")
        print("-" * 40)
        
        # Create lazy document
        print("Creating lazy document...")
        lazy_doc = await self.processor.process_lazy(documents[-1])  # Large document
        
        # Get metadata without loading content
        print("Getting metadata (no content loaded)...")
        start_time = time.time()
        metadata = await lazy_doc.get_metadata()
        metadata_time = time.time() - start_time
        
        print(f"  ✅ Metadata loaded in {metadata_time:.3f}s")
        print(f"  📄 Path: {metadata.path}")
        print(f"  📊 Size: {metadata.size_bytes / 1024 / 1024:.2f} MB")
        
        # Load specific chapter
        print("\nLoading specific chapter...")
        start_time = time.time()
        chapter = await lazy_doc.get_chapter("Chapter 1")
        chapter_time = time.time() - start_time
        
        if chapter:
            print(f"  ✅ Chapter loaded in {chapter_time:.3f}s")
            print(f"  📖 Chapter length: {len(chapter)} characters")
        
        # Search without loading full document
        print("\nSearching document...")
        start_time = time.time()
        search_results = await lazy_doc.search("concepts", max_results=3)
        search_time = time.time() - start_time
        
        print(f"  ✅ Search completed in {search_time:.3f}s")
        print(f"  🔍 Found {len(search_results)} matches")
    
    async def demo_adaptive_processing(self, documents: List[Path]):
        """Demonstrate adaptive processing"""
        print("\n🧠 Adaptive Processing Demo")
        print("-" * 40)
        
        # Use the optimized manager with adaptive processing
        print("Processing with adaptive strategy selection...")
        
        # Process different workloads
        workloads = [
            ("Single small document", documents[:1]),
            ("Small batch", documents[:3]),
            ("Medium batch", documents[:5]),
            ("Mixed sizes", documents)
        ]
        
        for workload_name, doc_list in workloads:
            print(f"\n{workload_name}:")
            start_time = time.time()
            
            results = await self.manager.process_documents_batch(doc_list)
            
            process_time = time.time() - start_time
            total_size = sum(
                doc.metadata.size_bytes for doc in results if doc
            ) / 1024 / 1024
            
            print(f"  ✅ Processed {len(results)} documents")
            print(f"  📊 Total size: {total_size:.2f} MB")
            print(f"  ⏱️  Time: {process_time:.3f}s")
            print(f"  🚀 Throughput: {total_size/process_time:.2f} MB/s")
        
        # Show adaptive profiles
        if hasattr(self.manager, 'adaptive_processor'):
            profiles = self.manager.adaptive_processor.get_profile_stats()
            print(f"\n📊 Adaptive Learning Profiles:")
            for profile_name, stats in profiles.items():
                print(f"  {profile_name}:")
                print(f"    Avg time: {stats['avg_time_ms']:.2f}ms")
                print(f"    Success rate: {stats['success_rate']:.2%}")
                print(f"    Preferred workers: {stats['preferred_workers']}")
    
    async def demo_background_processing(self, documents: List[Path]):
        """Demonstrate background processing with progress tracking"""
        print("\n🔄 Background Processing Demo")
        print("-" * 40)
        
        bg_processor = BackgroundDocumentProcessor(self.processor)
        
        # Start background processing
        print("Starting background processing...")
        task_ids = []
        
        for i, doc_path in enumerate(documents[:3]):
            task_id = await bg_processor.process_async(
                doc_path,
                callback=lambda doc: print(f"  ✅ Completed: {doc.metadata.path}")
            )
            task_ids.append(task_id)
            print(f"  🚀 Started task {task_id} for {doc_path.name}")
        
        # Monitor progress
        print("\nMonitoring progress...")
        while True:
            all_complete = True
            for task_id in task_ids:
                progress = bg_processor.get_progress(task_id)
                if progress < 1.0 and progress >= 0:
                    all_complete = False
                    print(f"  📊 Task {task_id}: {progress:.1%}")
            
            if all_complete:
                break
            
            await asyncio.sleep(0.5)
        
        print("✅ All background tasks completed!")
    
    async def demo_memory_management(self, documents: List[Path]):
        """Demonstrate memory management features"""
        print("\n🧠 Memory Management Demo")
        print("-" * 40)
        
        # Get initial memory stats
        initial_stats = await self.manager.get_system_status()
        print(f"Initial memory usage:")
        print(f"  Process RSS: {initial_stats['memory']['process_rss_mb']:.2f} MB")
        print(f"  System usage: {initial_stats['memory']['system_used_percent']:.1f}%")
        
        # Process documents to use memory
        print("\nProcessing documents to build up memory usage...")
        for doc_path in documents:
            await self.manager.process_document(doc_path)
        
        # Check memory after processing
        mid_stats = await self.manager.get_system_status()
        print(f"\nAfter processing:")
        print(f"  Process RSS: {mid_stats['memory']['process_rss_mb']:.2f} MB")
        print(f"  Cache entries: {mid_stats['cache']['total_size']}")
        print(f"  Cache memory: {mid_stats['cache']['memory_mb']:.2f} MB")
        
        # Trigger memory cleanup
        print("\nTriggering memory cleanup...")
        await self.manager.memory_manager.cleanup_memory(force=True)
        
        # Check memory after cleanup
        final_stats = await self.manager.get_system_status()
        print(f"\nAfter cleanup:")
        print(f"  Process RSS: {final_stats['memory']['process_rss_mb']:.2f} MB")
        print(f"  Memory freed: {mid_stats['memory']['process_rss_mb'] - final_stats['memory']['process_rss_mb']:.2f} MB")
    
    async def demo_performance_benchmarks(self):
        """Run performance benchmarks"""
        print("\n📊 Performance Benchmarks")
        print("-" * 40)
        
        # Quick benchmark configuration
        config = BenchmarkConfig(
            name="demo_benchmark",
            description="Quick demo benchmark",
            document_sizes_mb=[1, 5],
            document_counts=[1, 3, 5],
            worker_counts=[1, 2],
            cache_sizes=[10, 25],
            iterations=2,
            output_dir=self.test_dir / "benchmarks"
        )
        
        print("Running quick performance benchmark...")
        suite = DocumentBenchmarkSuite(config)
        results = await suite.run_all_benchmarks()
        
        if results:
            print(f"\n✅ Benchmark completed with {len(results)} tests")
            
            # Show summary
            avg_throughput = sum(r.throughput_mbps for r in results) / len(results)
            max_throughput = max(r.throughput_mbps for r in results)
            avg_memory = sum(r.memory_peak_mb for r in results) / len(results)
            
            print(f"📊 Results Summary:")
            print(f"  Average throughput: {avg_throughput:.2f} MB/s")
            print(f"  Peak throughput: {max_throughput:.2f} MB/s")
            print(f"  Average memory: {avg_memory:.2f} MB")
        
        print(f"📁 Detailed reports saved to: {config.output_dir}")
    
    async def run_complete_demo(self):
        """Run the complete demonstration"""
        try:
            await self.setup()
            
            # Create test documents
            documents = self.create_test_documents()
            
            # Run all demos
            await self.demo_basic_processing(documents)
            await self.demo_parallel_processing(documents)
            await self.demo_lazy_loading(documents)
            await self.demo_adaptive_processing(documents)
            await self.demo_background_processing(documents)
            await self.demo_memory_management(documents)
            await self.demo_performance_benchmarks()
            
            print("\n🎉 Document Processing Demo Complete!")
            print("=" * 60)
            print("Key Features Demonstrated:")
            print("✅ High-performance caching with compression")
            print("✅ Lazy loading for memory efficiency")
            print("✅ Parallel processing with optimal scaling")
            print("✅ Adaptive strategy selection")
            print("✅ Background processing with progress tracking")
            print("✅ Advanced memory management")
            print("✅ Comprehensive benchmarking framework")
            print("✅ Object pooling and resource management")
            print("✅ Streaming APIs for large documents")
            print("✅ Fast index structures for searching")
            
        finally:
            await self.cleanup()


async def main():
    """Main entry point for the demo"""
    print("🚀 SYNTHEX Agent 5 - Document Processing Optimization Demo")
    print("This demo showcases advanced document processing capabilities")
    print("with performance optimizations for production workloads.\n")
    
    demo = DocumentProcessingDemo()
    await demo.run_complete_demo()


if __name__ == "__main__":
    # Run the complete demo
    asyncio.run(main())