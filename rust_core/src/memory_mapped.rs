// ============================================================================
// Memory-Mapped I/O Module - Zero-Copy File Operations
// ============================================================================
// This module provides high-performance, zero-copy file operations using
// memory mapping for optimal performance with large files and data streams.
//
// Key features:
// - Memory-mapped file reading with zero-copy semantics
// - Concurrent access with lock-free operations
// - SIMD-optimized data processing
// - Efficient search and pattern matching
// - Support for huge files (>4GB)
// ============================================================================

use pyo3::prelude::*;
use memmap2::{Mmap, MmapOptions};
use std::fs::File;

use std::sync::Arc;
use parking_lot::RwLock;
use std::simd::{i8x32, Simd};
use dashmap::DashMap;
use rayon::prelude::*;
use tracing::{info, debug, warn};

// #[cfg(all(feature = "simd", not(target_arch = "wasm32")))]
// use wide::{i8x32, CmpEq};

use crate::{CoreError, CoreResult};

/// Register memory-mapped functions with Python module
pub fn register_module(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<MemoryMappedFile>()?;
    m.add_class::<MemoryMappedCache>()?;
    m.add_function(wrap_pyfunction!(mmap_search_parallel_py, m)?)?;
    m.add_function(wrap_pyfunction!(mmap_process_lines_py, m)?)?;
    Ok(())
}

// ========================= Memory-Mapped File =========================

#[pyclass]
pub struct MemoryMappedFile {
    mmap: Arc<Mmap>,
    file_size: usize,
    chunk_size: usize,
}

#[pymethods]
impl MemoryMappedFile {
    #[new]
    fn new(file_path: String, chunk_size: Option<usize>) -> PyResult<Self> {
        let file = File::open(&file_path)
            .map_err(|e| CoreError::Io(e))?;
        
        let mmap = unsafe { MmapOptions::new().map(&file) }
            .map_err(|e| CoreError::Io(e))?;
        
        let file_size = mmap.len();
        let chunk_size = chunk_size.unwrap_or(64 * 1024); // 64KB default
        
        info!("Memory-mapped file {} ({} bytes)", file_path, file_size);
        
        Ok(Self {
            mmap: Arc::new(mmap),
            file_size,
            chunk_size,
        })
    }
    
    /// Get file size
    fn size(&self) -> usize {
        self.file_size
    }
    
    /// Read a slice of the file without copying
    fn read_slice(&self, start: usize, length: usize) -> PyResult<Vec<u8>> {
        if start + length > self.file_size {
            return Err(CoreError::Performance("Read beyond file boundary".to_string()).into());
        }
        
        // This is unfortunately a copy for Python compatibility
        // In pure Rust, we'd return a slice reference
        Ok(self.mmap[start..start + length].to_vec())
    }
    
    /// Search for a pattern in the file using parallel processing
    fn search_pattern(&self, pattern: &[u8]) -> PyResult<Vec<usize>> {
        if pattern.is_empty() {
            return Ok(Vec::new());
        }
        
        let positions = search_pattern_parallel(&self.mmap, pattern, self.chunk_size)?;
        debug!("Found {} occurrences of pattern", positions.len());
        Ok(positions)
    }
    
    /// Count lines in the file using parallel processing
    fn count_lines(&self) -> PyResult<usize> {
        let line_count = count_lines_parallel(&self.mmap, self.chunk_size)?;
        debug!("Counted {} lines in file", line_count);
        Ok(line_count)
    }
    
    /// Process file in chunks with a callback-like operation
    fn process_chunks(&self, operation: &str) -> PyResult<Vec<f64>> {
        let results = match operation {
            "checksum" => compute_checksums_parallel(&self.mmap, self.chunk_size)?,
            "word_count" => count_words_parallel(&self.mmap, self.chunk_size)?,
            _ => return Err(CoreError::Performance("Unknown operation".to_string()).into()),
        };
        
        debug!("Processed {} chunks with operation '{}'", results.len(), operation);
        Ok(results)
    }
}

// ========================= Memory-Mapped Cache =========================

#[pyclass]
pub struct MemoryMappedCache {
    cache: Arc<DashMap<String, Arc<Mmap>>>,
    max_size: usize,
    current_size: Arc<RwLock<usize>>,
}

#[pymethods]
impl MemoryMappedCache {
    #[new]
    fn new(max_size_mb: usize) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            max_size: max_size_mb * 1024 * 1024, // Convert MB to bytes
            current_size: Arc::new(RwLock::new(0)),
        }
    }
    
    /// Load a file into cache
    fn load_file(&self, file_path: String) -> PyResult<bool> {
        if self.cache.contains_key(&file_path) {
            return Ok(true); // Already cached
        }
        
        let file = File::open(&file_path)
            .map_err(|e| CoreError::Io(e))?;
        
        let mmap = unsafe { MmapOptions::new().map(&file) }
            .map_err(|e| CoreError::Io(e))?;
        
        let file_size = mmap.len();
        
        // Check if we have space
        {
            let current_size = *self.current_size.read();
            if current_size + file_size > self.max_size {
                warn!("Cache full, cannot load file {} ({} bytes)", file_path, file_size);
                return Ok(false);
            }
        }
        
        // Add to cache
        let mmap_arc = Arc::new(mmap);
        self.cache.insert(file_path.clone(), mmap_arc);
        
        // Update size
        {
            let mut current_size = self.current_size.write();
            *current_size += file_size;
        }
        
        info!("Cached file {} ({} bytes)", file_path, file_size);
        Ok(true)
    }
    
    /// Search pattern across all cached files
    fn search_all(&self, pattern: Vec<u8>) -> PyResult<Vec<(String, Vec<usize>)>> {
        let cache_entries: Vec<_> = self.cache.iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();
        
        let results: Vec<(String, Vec<usize>)> = cache_entries
            .par_iter()
            .map(|(file_path, mmap)| {
                let positions = search_pattern_parallel(mmap, &pattern, 64 * 1024)
                    .unwrap_or_else(|_| Vec::new());
                (file_path.clone(), positions)
            })
            .filter(|(_, positions)| !positions.is_empty())
            .collect();
        
        debug!("Searched {} cached files, found matches in {}", 
               self.cache.len(), results.len());
        Ok(results)
    }
    
    /// Get cache statistics
    fn get_stats(&self) -> PyResult<std::collections::HashMap<String, usize>> {
        let mut stats = std::collections::HashMap::new();
        stats.insert("cached_files".to_string(), self.cache.len());
        stats.insert("total_size_bytes".to_string(), *self.current_size.read());
        stats.insert("max_size_bytes".to_string(), self.max_size);
        Ok(stats)
    }
    
    /// Clear cache
    fn clear(&self) {
        self.cache.clear();
        *self.current_size.write() = 0;
        info!("Memory-mapped cache cleared");
    }
}

// ========================= Core Functions =========================

/// Search for a pattern using parallel processing
#[inline]
fn search_pattern_parallel(
    data: &[u8], 
    pattern: &[u8], 
    chunk_size: usize
) -> CoreResult<Vec<usize>> {
    if pattern.is_empty() || data.is_empty() {
        return Ok(Vec::new());
    }
    
    let pattern_len = pattern.len();
    if pattern_len > data.len() {
        return Ok(Vec::new());
    }
    
    let chunks: Vec<_> = data
        .chunks(chunk_size)
        .enumerate()
        .collect();
    
    let positions: Vec<usize> = chunks
        .into_par_iter()
        .flat_map(|(chunk_idx, chunk)| {
            let chunk_start = chunk_idx * chunk_size;
            search_pattern_simd(chunk, pattern)
                .into_iter()
                .map(move |pos| chunk_start + pos)
                .collect::<Vec<_>>()
        })
        .collect();
    
    Ok(positions)
}

/// SIMD-optimized pattern search (fallback to naive if SIMD not available)
#[cfg(all(feature = "simd", not(target_arch = "wasm32")))]
#[inline]
fn search_pattern_simd(data: &[u8], pattern: &[u8]) -> Vec<usize> {
    if pattern.len() == 1 {
        return search_single_byte_simd(data, pattern[0]);
    }
    
    // For multi-byte patterns, use Boyer-Moore-like approach with SIMD for first byte
    let first_byte = pattern[0];
    let first_byte_positions = search_single_byte_simd(data, first_byte);
    
    first_byte_positions
        .into_iter()
        .filter(|&pos| {
            pos + pattern.len() <= data.len() && 
            &data[pos..pos + pattern.len()] == pattern
        })
        .collect()
}

#[cfg(all(feature = "simd", not(target_arch = "wasm32")))]
fn search_single_byte_simd(data: &[u8], target: u8) -> Vec<usize> {
    // use wide::i8x32;
    let mut positions = Vec::new();
    let target_vec = i8x32::splat(target as i8);
    
    let mut i = 0;
    while i + 32 <= data.len() {
        let chunk = i8x32::new([
            data[i] as i8, data[i+1] as i8, data[i+2] as i8, data[i+3] as i8,
            data[i+4] as i8, data[i+5] as i8, data[i+6] as i8, data[i+7] as i8,
            data[i+8] as i8, data[i+9] as i8, data[i+10] as i8, data[i+11] as i8,
            data[i+12] as i8, data[i+13] as i8, data[i+14] as i8, data[i+15] as i8,
            data[i+16] as i8, data[i+17] as i8, data[i+18] as i8, data[i+19] as i8,
            data[i+20] as i8, data[i+21] as i8, data[i+22] as i8, data[i+23] as i8,
            data[i+24] as i8, data[i+25] as i8, data[i+26] as i8, data[i+27] as i8,
            data[i+28] as i8, data[i+29] as i8, data[i+30] as i8, data[i+31] as i8,
        ]);
        
        let mask = chunk.cmp_eq(target_vec);
        let mask_array = mask.to_array();
        
        for (j, &is_match) in mask_array.iter().enumerate() {
            if is_match != 0 {
                positions.push(i + j);
            }
        }
        
        i += 32;
    }
    
    // Handle remaining bytes
    for j in i..data.len() {
        if data[j] == target {
            positions.push(j);
        }
    }
    
    positions
}

#[cfg(not(feature = "simd"))]
fn search_pattern_simd(data: &[u8], pattern: &[u8]) -> Vec<usize> {
    // Fallback to naive search
    data.windows(pattern.len())
        .enumerate()
        .filter_map(|(i, window)| {
            if window == pattern { Some(i) } else { None }
        })
        .collect()
}

/// Count lines using parallel processing
fn count_lines_parallel(data: &[u8], chunk_size: usize) -> CoreResult<usize> {
    let total_lines: usize = data
        .par_chunks(chunk_size)
        .map(|chunk| chunk.iter().filter(|&&b| b == b'\n').count())
        .sum();
    
    Ok(total_lines)
}

/// Compute checksums for chunks in parallel
fn compute_checksums_parallel(data: &[u8], chunk_size: usize) -> CoreResult<Vec<f64>> {
    let checksums: Vec<f64> = data
        .par_chunks(chunk_size)
        .map(|chunk| {
            chunk.iter().map(|&b| b as u64).sum::<u64>() as f64
        })
        .collect();
    
    Ok(checksums)
}

/// Count words in chunks using parallel processing
fn count_words_parallel(data: &[u8], chunk_size: usize) -> CoreResult<Vec<f64>> {
    let word_counts: Vec<f64> = data
        .par_chunks(chunk_size)
        .map(|chunk| {
            let mut count = 0;
            let mut in_word = false;
            
            for &byte in chunk {
                let is_whitespace = byte.is_ascii_whitespace();
                if !is_whitespace && !in_word {
                    count += 1;
                    in_word = true;
                } else if is_whitespace {
                    in_word = false;
                }
            }
            
            count as f64
        })
        .collect();
    
    Ok(word_counts)
}

// ========================= Python Functions =========================

#[pyfunction]
fn mmap_search_parallel_py(
    py: Python,
    file_path: String,
    pattern: Vec<u8>,
    chunk_size: Option<usize>
) -> PyResult<Vec<usize>> {
    py.allow_threads(|| {
        let file = File::open(&file_path)
            .map_err(|e| CoreError::Io(e))?;
        
        let mmap = unsafe { MmapOptions::new().map(&file) }
            .map_err(|e| CoreError::Io(e))?;
        
        let chunk_size = chunk_size.unwrap_or(64 * 1024);
        search_pattern_parallel(&mmap, &pattern, chunk_size)
            .map_err(|e| e.into())
    })
}

#[pyfunction]
fn mmap_process_lines_py(
    py: Python,
    file_path: String,
    operation: String
) -> PyResult<usize> {
    py.allow_threads(|| {
        let file = File::open(&file_path)
            .map_err(|e| CoreError::Io(e))?;
        
        let mmap = unsafe { MmapOptions::new().map(&file) }
            .map_err(|e| CoreError::Io(e))?;
        
        match operation.as_str() {
            "count" => count_lines_parallel(&mmap, 64 * 1024)
                .map_err(|e| e.into()),
            _ => Err(CoreError::Performance("Unknown operation".to_string()).into()),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::fs;
    
    #[test]
    fn test_memory_mapped_file() {
        // Create a test file
        let test_content = b"Hello World\nThis is a test\nAnother line\n";
        let test_file = "/tmp/test_mmap.txt";
        fs::write(test_file, test_content).unwrap();
        
        Python::with_gil(|py| {
            let mmap_file = MemoryMappedFile::new(test_file.to_string(), None).unwrap();
            
            assert_eq!(mmap_file.size(), test_content.len());
            
            let slice = mmap_file.read_slice(0, 5).unwrap();
            assert_eq!(slice, b"Hello");
            
            let line_count = mmap_file.count_lines().unwrap();
            assert_eq!(line_count, 3);
        });
        
        // Cleanup
        fs::remove_file(test_file).ok();
    }
    
    #[test]
    fn test_pattern_search() {
        let data = b"abcdefabcdefabcdef";
        let pattern = b"abc";
        
        let positions = search_pattern_simd(data, pattern);
        assert_eq!(positions, vec![0, 6, 12]);
    }
    
    #[test]
    fn test_memory_mapped_cache() {
        Python::with_gil(|py| {
            let cache = MemoryMappedCache::new(10); // 10MB max
            
            let stats = cache.get_stats().unwrap();
            assert_eq!(stats["cached_files"], 0);
            assert_eq!(stats["total_size_bytes"], 0);
        });
    }
}