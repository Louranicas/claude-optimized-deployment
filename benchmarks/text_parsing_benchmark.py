"""
Text Parsing Performance Benchmark
Tests different parsing libraries and approaches
"""

import time
import psutil
import os
from pathlib import Path
from typing import Dict, List, Any
import json
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import tempfile
import random
import string

# Optional imports
try:
    import PyPDF2
except ImportError:
    PyPDF2 = None

try:
    import pdfplumber
except ImportError:
    pdfplumber = None

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

try:
    from docx import Document
except ImportError:
    Document = None


class TextParsingBenchmark:
    """Benchmark different text parsing approaches"""
    
    def __init__(self, output_dir: Path = Path("./benchmark_results")):
        self.output_dir = output_dir
        self.output_dir.mkdir(exist_ok=True)
        self.results = []
        
    def benchmark_pdf_libraries(self, pdf_path: Path) -> Dict[str, Any]:
        """Benchmark different PDF parsing libraries"""
        results = {}
        file_size_mb = pdf_path.stat().st_size / (1024 * 1024)
        
        # Benchmark PyPDF2
        if PyPDF2:
            start_time = time.time()
            start_memory = psutil.Process().memory_info().rss / 1024 / 1024
            
            try:
                with open(pdf_path, 'rb') as file:
                    reader = PyPDF2.PdfReader(file)
                    text_length = 0
                    for page in reader.pages:
                        text = page.extract_text()
                        text_length += len(text)
                        
                end_time = time.time()
                end_memory = psutil.Process().memory_info().rss / 1024 / 1024
                
                results['pypdf2'] = {
                    'time': end_time - start_time,
                    'memory_mb': end_memory - start_memory,
                    'text_chars': text_length,
                    'pages_per_second': len(reader.pages) / (end_time - start_time),
                    'mb_per_second': file_size_mb / (end_time - start_time)
                }
            except Exception as e:
                results['pypdf2'] = {'error': str(e)}
                
        # Benchmark pdfplumber
        if pdfplumber:
            start_time = time.time()
            start_memory = psutil.Process().memory_info().rss / 1024 / 1024
            
            try:
                with pdfplumber.open(pdf_path) as pdf:
                    text_length = 0
                    table_count = 0
                    for page in pdf.pages:
                        text = page.extract_text() or ""
                        text_length += len(text)
                        tables = page.extract_tables()
                        if tables:
                            table_count += len(tables)
                            
                end_time = time.time()
                end_memory = psutil.Process().memory_info().rss / 1024 / 1024
                
                results['pdfplumber'] = {
                    'time': end_time - start_time,
                    'memory_mb': end_memory - start_memory,
                    'text_chars': text_length,
                    'tables_found': table_count,
                    'pages_per_second': len(pdf.pages) / (end_time - start_time),
                    'mb_per_second': file_size_mb / (end_time - start_time)
                }
            except Exception as e:
                results['pdfplumber'] = {'error': str(e)}
                
        # Benchmark PyMuPDF
        if fitz:
            start_time = time.time()
            start_memory = psutil.Process().memory_info().rss / 1024 / 1024
            
            try:
                doc = fitz.open(pdf_path)
                text_length = 0
                for page in doc:
                    text = page.get_text()
                    text_length += len(text)
                    
                page_count = len(doc)
                doc.close()
                
                end_time = time.time()
                end_memory = psutil.Process().memory_info().rss / 1024 / 1024
                
                results['pymupdf'] = {
                    'time': end_time - start_time,
                    'memory_mb': end_memory - start_memory,
                    'text_chars': text_length,
                    'pages_per_second': page_count / (end_time - start_time),
                    'mb_per_second': file_size_mb / (end_time - start_time)
                }
            except Exception as e:
                results['pymupdf'] = {'error': str(e)}
                
        return results
        
    def benchmark_streaming_vs_full_load(self, text_path: Path) -> Dict[str, Any]:
        """Compare streaming vs full file loading for text files"""
        results = {}
        file_size_mb = text_path.stat().st_size / (1024 * 1024)
        
        # Full load approach
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        try:
            with open(text_path, 'r', encoding='utf-8') as file:
                content = file.read()
                line_count = content.count('\n')
                
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss / 1024 / 1024
            
            results['full_load'] = {
                'time': end_time - start_time,
                'memory_mb': end_memory - start_memory,
                'lines': line_count,
                'mb_per_second': file_size_mb / (end_time - start_time)
            }
        except Exception as e:
            results['full_load'] = {'error': str(e)}
            
        # Streaming approach
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        try:
            line_count = 0
            with open(text_path, 'r', encoding='utf-8') as file:
                for line in file:
                    line_count += 1
                    
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss / 1024 / 1024
            
            results['streaming'] = {
                'time': end_time - start_time,
                'memory_mb': end_memory - start_memory,
                'lines': line_count,
                'mb_per_second': file_size_mb / (end_time - start_time)
            }
        except Exception as e:
            results['streaming'] = {'error': str(e)}
            
        # Chunked streaming
        chunk_size = 1024 * 1024  # 1MB chunks
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        try:
            line_count = 0
            with open(text_path, 'r', encoding='utf-8') as file:
                while True:
                    chunk = file.read(chunk_size)
                    if not chunk:
                        break
                    line_count += chunk.count('\n')
                    
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss / 1024 / 1024
            
            results['chunked_streaming'] = {
                'time': end_time - start_time,
                'memory_mb': end_memory - start_memory,
                'lines': line_count,
                'chunk_size': chunk_size,
                'mb_per_second': file_size_mb / (end_time - start_time)
            }
        except Exception as e:
            results['chunked_streaming'] = {'error': str(e)}
            
        return results
        
    def benchmark_parallel_processing(self, file_paths: List[Path]) -> Dict[str, Any]:
        """Benchmark parallel vs sequential processing"""
        results = {}
        
        # Sequential processing
        start_time = time.time()
        total_chars = 0
        
        for path in file_paths:
            try:
                with open(path, 'r', encoding='utf-8') as file:
                    content = file.read()
                    total_chars += len(content)
            except:
                pass
                
        end_time = time.time()
        results['sequential'] = {
            'time': end_time - start_time,
            'files_processed': len(file_paths),
            'total_chars': total_chars,
            'files_per_second': len(file_paths) / (end_time - start_time)
        }
        
        # Thread pool processing
        start_time = time.time()
        total_chars = 0
        
        def process_file(path):
            try:
                with open(path, 'r', encoding='utf-8') as file:
                    return len(file.read())
            except:
                return 0
                
        with ThreadPoolExecutor(max_workers=4) as executor:
            char_counts = list(executor.map(process_file, file_paths))
            total_chars = sum(char_counts)
            
        end_time = time.time()
        results['thread_pool'] = {
            'time': end_time - start_time,
            'files_processed': len(file_paths),
            'total_chars': total_chars,
            'files_per_second': len(file_paths) / (end_time - start_time),
            'workers': 4
        }
        
        # Process pool processing
        start_time = time.time()
        
        with ProcessPoolExecutor(max_workers=4) as executor:
            char_counts = list(executor.map(process_file, file_paths))
            total_chars = sum(char_counts)
            
        end_time = time.time()
        results['process_pool'] = {
            'time': end_time - start_time,
            'files_processed': len(file_paths),
            'total_chars': total_chars,
            'files_per_second': len(file_paths) / (end_time - start_time),
            'workers': 4
        }
        
        return results
        
    def generate_test_files(self, temp_dir: Path) -> Dict[str, Path]:
        """Generate test files for benchmarking"""
        test_files = {}
        
        # Generate large text file (10MB)
        large_text_path = temp_dir / "large_text.txt"
        with open(large_text_path, 'w') as file:
            for i in range(100000):
                line = ''.join(random.choices(string.ascii_letters + string.digits, k=100))
                file.write(f"{line}\n")
        test_files['large_text'] = large_text_path
        
        # Generate medium text file (1MB)
        medium_text_path = temp_dir / "medium_text.txt"
        with open(medium_text_path, 'w') as file:
            for i in range(10000):
                line = ''.join(random.choices(string.ascii_letters + string.digits, k=100))
                file.write(f"{line}\n")
        test_files['medium_text'] = medium_text_path
        
        # Generate multiple small files for parallel testing
        small_files = []
        for i in range(20):
            small_path = temp_dir / f"small_{i}.txt"
            with open(small_path, 'w') as file:
                for j in range(1000):
                    line = ''.join(random.choices(string.ascii_letters + string.digits, k=100))
                    file.write(f"{line}\n")
            small_files.append(small_path)
        test_files['small_files'] = small_files
        
        return test_files
        
    def run_comprehensive_benchmark(self):
        """Run all benchmarks and save results"""
        print("Starting comprehensive text parsing benchmark...")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            test_files = self.generate_test_files(temp_path)
            
            # Benchmark streaming approaches
            print("\n1. Benchmarking streaming vs full load...")
            streaming_results = self.benchmark_streaming_vs_full_load(
                test_files['large_text']
            )
            self.results.append({
                'test': 'streaming_comparison',
                'file_size_mb': test_files['large_text'].stat().st_size / (1024 * 1024),
                'results': streaming_results
            })
            
            # Benchmark parallel processing
            print("\n2. Benchmarking parallel processing...")
            parallel_results = self.benchmark_parallel_processing(
                test_files['small_files']
            )
            self.results.append({
                'test': 'parallel_processing',
                'file_count': len(test_files['small_files']),
                'results': parallel_results
            })
            
            # Memory usage patterns
            print("\n3. Testing memory usage patterns...")
            memory_results = self._test_memory_patterns(test_files)
            self.results.append({
                'test': 'memory_patterns',
                'results': memory_results
            })
            
        # Save results
        self._save_results()
        self._print_summary()
        
    def _test_memory_patterns(self, test_files: Dict[str, Any]) -> Dict[str, Any]:
        """Test memory usage patterns for different approaches"""
        results = {}
        
        # Test incremental memory usage
        file_path = test_files['large_text']
        chunk_sizes = [1024, 1024*10, 1024*100, 1024*1024]  # 1KB to 1MB
        
        for chunk_size in chunk_sizes:
            start_memory = psutil.Process().memory_info().rss / 1024 / 1024
            peak_memory = start_memory
            
            with open(file_path, 'r', encoding='utf-8') as file:
                while True:
                    chunk = file.read(chunk_size)
                    if not chunk:
                        break
                    current_memory = psutil.Process().memory_info().rss / 1024 / 1024
                    peak_memory = max(peak_memory, current_memory)
                    
            results[f'chunk_{chunk_size}'] = {
                'chunk_size_kb': chunk_size / 1024,
                'peak_memory_mb': peak_memory - start_memory
            }
            
        return results
        
    def _save_results(self):
        """Save benchmark results to JSON"""
        output_file = self.output_dir / f"text_parsing_benchmark_{int(time.time())}.json"
        
        with open(output_file, 'w') as f:
            json.dump({
                'timestamp': time.time(),
                'cpu_count': multiprocessing.cpu_count(),
                'total_memory_gb': psutil.virtual_memory().total / (1024**3),
                'results': self.results
            }, f, indent=2)
            
        print(f"\nResults saved to: {output_file}")
        
    def _print_summary(self):
        """Print benchmark summary"""
        print("\n" + "="*60)
        print("BENCHMARK SUMMARY")
        print("="*60)
        
        for result in self.results:
            print(f"\n{result['test'].upper()}:")
            
            if result['test'] == 'streaming_comparison':
                for method, data in result['results'].items():
                    if 'error' not in data:
                        print(f"  {method}:")
                        print(f"    Time: {data['time']:.2f}s")
                        print(f"    Memory: {data['memory_mb']:.2f}MB")
                        print(f"    Speed: {data['mb_per_second']:.2f}MB/s")
                        
            elif result['test'] == 'parallel_processing':
                for method, data in result['results'].items():
                    print(f"  {method}:")
                    print(f"    Time: {data['time']:.2f}s")
                    print(f"    Files/s: {data['files_per_second']:.2f}")
                    
            elif result['test'] == 'memory_patterns':
                print("  Chunk size vs Memory usage:")
                for chunk_type, data in result['results'].items():
                    print(f"    {data['chunk_size_kb']:.0f}KB chunks: "
                          f"{data['peak_memory_mb']:.2f}MB peak memory")


if __name__ == "__main__":
    benchmark = TextParsingBenchmark()
    benchmark.run_comprehensive_benchmark()
    
    # Additional PDF benchmark if you have a PDF file
    # pdf_path = Path("sample.pdf")
    # if pdf_path.exists():
    #     pdf_results = benchmark.benchmark_pdf_libraries(pdf_path)
    #     print("\nPDF Library Comparison:")
    #     for lib, data in pdf_results.items():
    #         if 'error' not in data:
    #             print(f"  {lib}: {data['pages_per_second']:.1f} pages/s, "
    #                   f"{data['memory_mb']:.1f}MB memory")