Python FFI API Reference
========================

The Python FFI (Foreign Function Interface) layer provides Python bindings for the Rust CBC Core, enabling high-performance operations from Python with seamless NumPy integration.

.. contents:: Table of Contents
   :local:

Overview
--------

The Python FFI layer (``anam_py``) provides:

* **HTMCore Python Class** - Direct Python interface to Rust HTM storage
* **AxiomValidator Python Interface** - NAM/ANAM validation from Python  
* **Async Operation Support** - Async/await compatible methods
* **NumPy Integration** - Native NumPy array handling for embeddings
* **Memory Management** - Efficient memory handling between Python and Rust

Installation
------------

.. code-block:: bash

   # Install from source
   cd anam_py
   pip install -e .
   
   # Or install wheel
   pip install anam_py-0.1.0-py3-none-any.whl

HTMCore Python Interface
------------------------

The ``HTMCore`` class provides Python access to the Rust HTM storage system.

Import and Initialization
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from anam_py import HTMCore
   import numpy as np
   
   # Initialize HTM storage
   htm = HTMCore(storage_path="./data/htm", shard_count=8)

Core Methods
^^^^^^^^^^^^

Storage Operations
""""""""""""""""""

.. code-block:: python

   class HTMCore:
       def __init__(self, storage_path: str, shard_count: int = 4) -> None:
           """Initialize HTM storage."""
           
       def store_embedding(
           self,
           key: str,
           embedding: np.ndarray,
           metadata: Dict[str, Any],
           diff_ops: Optional[List[Dict[str, Any]]] = None
       ) -> None:
           """Store embedding with metadata."""
           
       def get_embedding(self, key: str) -> Optional[Dict[str, Any]]:
           """Retrieve embedding by key."""
           
       def search_similar(
           self,
           query_embedding: np.ndarray,
           limit: int = 10,
           min_similarity: float = 0.5
       ) -> List[Tuple[str, float, Dict[str, Any]]]:
           """Search for similar embeddings."""

**Example:**

.. code-block:: python

   import numpy as np
   from anam_py import HTMCore
   
   # Initialize HTM
   htm = HTMCore("./data/htm_storage", shard_count=8)
   
   # Create embedding (768-dimensional)
   embedding = np.random.float32(768)
   embedding = embedding / np.linalg.norm(embedding)  # Normalize
   
   # Store with metadata
   metadata = {
       "language": "python",
       "file_type": "source",
       "size_bytes": 2048,
       "line_count": 75,
       "dependencies": ["numpy", "torch"]
   }
   
   htm.store_embedding("src/model.py", embedding, metadata)
   
   # Retrieve later
   result = htm.get_embedding("src/model.py")
   if result:
       print(f"Found embedding: {result['metadata']['language']}")
   
   # Search for similar files
   query = np.random.float32(768)
   similar = htm.search_similar(query, limit=5, min_similarity=0.7)
   
   for path, similarity, data in similar:
       print(f"{path}: {similarity:.3f}")

Async Operations
""""""""""""""""

.. code-block:: python

   class HTMCore:
       async def store_embedding_async(
           self,
           key: str,
           embedding: np.ndarray,
           metadata: Dict[str, Any],
           diff_ops: Optional[List[Dict[str, Any]]] = None
       ) -> None:
           """Store embedding asynchronously."""
           
       async def get_embedding_async(self, key: str) -> Optional[Dict[str, Any]]:
           """Retrieve embedding asynchronously."""
           
       async def search_similar_async(
           self,
           query_embedding: np.ndarray,
           limit: int = 10,
           min_similarity: float = 0.5
       ) -> List[Tuple[str, float, Dict[str, Any]]]:
           """Search asynchronously."""

**Example:**

.. code-block:: python

   import asyncio
   import numpy as np
   from anam_py import HTMCore
   
   async def main():
       htm = HTMCore("./data/htm_storage")
       
       # Store multiple embeddings concurrently
       tasks = []
       for i in range(10):
           embedding = np.random.float32(768)
           metadata = {"file_id": i, "type": "test"}
           task = htm.store_embedding_async(f"file_{i}.py", embedding, metadata)
           tasks.append(task)
       
       await asyncio.gather(*tasks)
       
       # Search asynchronously
       query = np.random.float32(768)
       results = await htm.search_similar_async(query, limit=5)
       print(f"Found {len(results)} similar files")
   
   # Run async
   asyncio.run(main())

Resonance Calculations
""""""""""""""""""""""

.. code-block:: python

   class HTMCore:
       def calculate_resonance(
           self,
           embedding1: np.ndarray,
           embedding2: np.ndarray
       ) -> float:
           """Calculate resonance between embeddings."""
           
       def query_by_resonance(
           self,
           min_resonance: float,
           max_results: Optional[int] = None
       ) -> List[Tuple[str, float, Dict[str, Any]]]:
           """Query by resonance threshold."""
           
       async def query_by_resonance_async(
           self,
           min_resonance: float,
           max_results: Optional[int] = None
       ) -> List[Tuple[str, float, Dict[str, Any]]]:
           """Async resonance query."""

**Example:**

.. code-block:: python

   # Calculate resonance between two embeddings
   emb1 = np.random.float32(768)
   emb2 = np.random.float32(768)
   
   resonance = htm.calculate_resonance(emb1, emb2)
   print(f"Resonance score: {resonance:.3f}")
   
   # Find high-resonance files
   high_resonance = htm.query_by_resonance(min_resonance=0.8, max_results=10)
   
   for path, score, data in high_resonance:
       print(f"High resonance: {path} ({score:.3f})")

AxiomValidator Python Interface
-------------------------------

Python interface for NAM/ANAM axiom validation.

Import and Initialization
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from anam_py import AxiomValidator, calculate_resonance_score, validate_nam_compliance
   
   # Initialize validator
   validator = AxiomValidator()

Core Methods
^^^^^^^^^^^^

.. code-block:: python

   class AxiomValidator:
       def __init__(self) -> None:
           """Initialize with all 67 axioms."""
           
       def validate_axiom(
           self,
           axiom_id: str,
           context_axioms: List[str] = None
       ) -> Dict[str, Any]:
           """Validate single axiom."""
           
       def validate_batch(
           self,
           axiom_ids: List[str],
           context_axioms: List[str] = None
       ) -> Dict[str, Any]:
           """Validate multiple axioms."""
           
       def calculate_resonance(self, axioms: List[str]) -> float:
           """Calculate axiom resonance."""
           
       def calculate_tension(
           self,
           proposed_axioms: List[str],
           context_axioms: List[str]
       ) -> float:
           """Calculate ethical tension."""
           
       def recommend_axioms(self, context: str) -> List[str]:
           """Recommend axioms for context."""

**Example:**

.. code-block:: python

   from anam_py import AxiomValidator
   
   # Create validator
   validator = AxiomValidator()
   
   # Validate ethical operation
   context = ["AX_LOVE_FORCE", "AX_EMPATHY_BRIDGE"]
   result = validator.validate_axiom("AX_NO_HARM", context)
   
   print(f"Valid: {result['is_valid']}")
   print(f"Resonance: {result['resonance_score']:.3f}")
   print(f"Tension: {result['ethical_tension']:.3f}")
   
   # Batch validation
   ethical_axioms = ["AX_NO_HARM", "AX_BENEFICENCE", "AX_AUTONOMY", "AX_JUSTICE"]
   batch_result = validator.validate_batch(ethical_axioms, context)
   
   print(f"Batch valid: {batch_result['batch_valid']}")
   print(f"Overall resonance: {batch_result['overall_resonance']:.3f}")
   
   # Get recommendations
   recommendations = validator.recommend_axioms("ethical decision making")
   print(f"Recommended axioms: {recommendations}")

Resonance Kernels
^^^^^^^^^^^^^^^^^

Advanced resonance calculations using PyTorch integration.

.. code-block:: python

   from anam_py.kernels import (
       ResonanceKernel,
       HarmonicKernel,
       EthicalGate,
       calculate_resonance_score,
       validate_nam_compliance
   )
   import torch

**ResonanceKernel:**

.. code-block:: python

   import torch
   from anam_py.kernels import ResonanceKernel, calculate_resonance_score
   
   # Create resonance kernel
   kernel = ResonanceKernel(n_harmonics=8)
   
   # Calculate resonance for embeddings
   embeddings = torch.randn(32, 768)  # Batch of embeddings
   t = 1.0  # Time parameter
   
   resonance_score = calculate_resonance_score(embeddings, kernel, t)
   
   print(f"Resonance: {resonance_score.value:.3f}")
   print(f"NAM compliant: {resonance_score.nam_compliant}")
   print(f"Ethical tension: {resonance_score.ethical_tension:.3f}")
   print(f"Valid: {resonance_score.is_valid}")

**HarmonicKernel:**

.. code-block:: python

   from anam_py.kernels import HarmonicKernel
   
   # Create harmonic field calculator
   harmonic = HarmonicKernel(spatial_dims=768, n_modes=16)
   
   # Calculate harmonic field
   positions = torch.randn(10, 768)  # 10 positions in 768D space
   t = 2.5  # Time
   
   field = harmonic(positions, t)
   print(f"Harmonic field shape: {field.shape}")  # [10, 16]

**EthicalGate:**

.. code-block:: python

   import numpy as np
   from anam_py.kernels import EthicalGate
   
   # Create ethical validator
   gate = EthicalGate(tension_threshold=0.35)
   
   # Validate action
   action_vector = np.array([0.1, 0.2, -0.05, 0.15])
   valid, tension = gate.validate(action_vector)
   
   print(f"Action valid: {valid}")
   print(f"Ethical tension: {tension:.3f}")
   
   # Check violation history
   print(f"Violations: {len(gate.violation_history)}")

NumPy Integration
-----------------

Seamless integration with NumPy arrays for high-performance operations.

Array Conversion
^^^^^^^^^^^^^^^^

.. code-block:: python

   import numpy as np
   from anam_py import HTMCore
   
   # NumPy arrays are automatically converted
   embedding = np.random.float32(768)
   
   # Different NumPy dtypes supported
   float64_emb = np.random.float64(768)
   float32_emb = embedding.astype(np.float32)
   
   htm = HTMCore("./data")
   htm.store_embedding("test", float32_emb, {})

Memory Management
^^^^^^^^^^^^^^^^^

.. code-block:: python

   class HTMCore:
       def get_memory_stats(self) -> Dict[str, int]:
           """Get memory usage statistics."""
           
       def garbage_collect(self, aggressive: bool = False) -> None:
           """Trigger garbage collection."""
           
       def clear_cache(self) -> None:
           """Clear internal caches."""

**Example:**

.. code-block:: python

   # Monitor memory usage
   stats = htm.get_memory_stats()
   print(f"Memory used: {stats['used_bytes'] / 1024 / 1024:.2f} MB")
   print(f"Cache size: {stats['cache_entries']}")
   
   # Clean up when needed
   if stats['used_bytes'] > 1024 * 1024 * 1024:  # 1GB
       htm.garbage_collect(aggressive=True)

Performance Utilities
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   class HTMCore:
       def benchmark_operations(
           self,
           num_operations: int = 1000
       ) -> Dict[str, float]:
           """Benchmark storage operations."""
           
       def enable_profiling(self, enabled: bool = True) -> None:
           """Enable performance profiling."""
           
       def get_profiling_data(self) -> Dict[str, Any]:
           """Get profiling statistics."""

**Example:**

.. code-block:: python

   # Benchmark performance
   htm.enable_profiling(True)
   
   benchmark_results = htm.benchmark_operations(1000)
   print(f"Store ops/sec: {benchmark_results['store_ops_per_sec']:.2f}")
   print(f"Retrieve ops/sec: {benchmark_results['retrieve_ops_per_sec']:.2f}")
   print(f"Search ops/sec: {benchmark_results['search_ops_per_sec']:.2f}")
   
   # Get detailed profiling
   profile_data = htm.get_profiling_data()
   for operation, stats in profile_data.items():
       print(f"{operation}: avg {stats['avg_duration_ms']:.2f}ms")

Code Base Crawler Interface
---------------------------

Python interface for the code base crawler functionality.

.. code-block:: python

   from anam_py import CodeBaseCrawler
   
   class CodeBaseCrawler:
       def __init__(self, htm_core: HTMCore) -> None:
           """Initialize with HTM storage."""
           
       def crawl_directory(
           self,
           path: str,
           include_patterns: List[str] = None,
           exclude_patterns: List[str] = None,
           extract_embeddings: bool = True
       ) -> List[Dict[str, Any]]:
           """Crawl directory for code files."""
           
       async def crawl_directory_async(
           self,
           path: str,
           include_patterns: List[str] = None,
           exclude_patterns: List[str] = None,
           extract_embeddings: bool = True,
           progress_callback: Optional[Callable] = None
       ) -> List[Dict[str, Any]]:
           """Async directory crawling."""
           
       def analyze_file(self, file_path: str) -> Dict[str, Any]:
           """Analyze single file."""

**Example:**

.. code-block:: python

   from anam_py import HTMCore, CodeBaseCrawler
   
   # Initialize
   htm = HTMCore("./data/htm")
   crawler = CodeBaseCrawler(htm)
   
   # Crawl Python files
   results = crawler.crawl_directory(
       path="./src",
       include_patterns=["*.py"],
       exclude_patterns=["*test*", "*__pycache__*"],
       extract_embeddings=True
   )
   
   print(f"Crawled {len(results)} files")
   
   for result in results:
       print(f"File: {result['path']}")
       print(f"Language: {result['metadata']['language']}")
       print(f"Lines: {result['metadata']['line_count']}")
       print(f"Complexity: {result['metadata']['complexity_score']:.2f}")

Multi-Agent Orchestrator
------------------------

High-level multi-agent coordination interface.

.. code-block:: python

   from anam_py import MultiAgentOrchestrator
   
   class MultiAgentOrchestrator:
       def __init__(self, htm_core: HTMCore) -> None:
           """Initialize orchestrator."""
           
       def add_agent(self, agent_id: str, capabilities: List[str]) -> None:
           """Register agent with capabilities."""
           
       async def coordinate_task(
           self,
           task: Dict[str, Any],
           required_capabilities: List[str]
       ) -> Dict[str, Any]:
           """Coordinate task across agents."""
           
       def get_agent_status(self) -> Dict[str, Dict[str, Any]]:
           """Get status of all agents."""

**Example:**

.. code-block:: python

   import asyncio
   from anam_py import HTMCore, MultiAgentOrchestrator
   
   async def main():
       htm = HTMCore("./data")
       orchestrator = MultiAgentOrchestrator(htm)
       
       # Register agents
       orchestrator.add_agent("analyzer", ["code_analysis", "ast_parsing"])
       orchestrator.add_agent("embedder", ["embedding_generation", "similarity_search"])
       orchestrator.add_agent("validator", ["nam_validation", "ethical_checking"])
       
       # Coordinate complex task
       task = {
           "type": "code_review",
           "files": ["src/main.py", "src/utils.py"],
           "requirements": ["security_check", "quality_analysis"]
       }
       
       result = await orchestrator.coordinate_task(
           task,
           required_capabilities=["code_analysis", "nam_validation"]
       )
       
       print(f"Task completed: {result['success']}")
       print(f"Agents used: {result['agents_involved']}")
   
   asyncio.run(main())

Error Handling
--------------

Comprehensive error handling with Python exceptions.

.. code-block:: python

   from anam_py.exceptions import (
       HTMError,
       ValidationError,
       AxiomError,
       CrawlerError,
       MemoryError
   )
   
   try:
       htm = HTMCore("invalid/path")
   except HTMError as e:
       print(f"HTM initialization failed: {e}")
   
   try:
       validator = AxiomValidator()
       result = validator.validate_axiom("INVALID_AXIOM")
   except AxiomError as e:
       print(f"Axiom validation failed: {e}")

Context Managers
----------------

Use context managers for automatic cleanup.

.. code-block:: python

   from anam_py import HTMCore
   
   # Automatic cleanup
   with HTMCore("./data") as htm:
       htm.store_embedding("test", embedding, metadata)
       results = htm.search_similar(query)
   # HTM automatically cleaned up

Thread Safety
--------------

All Python FFI operations are thread-safe and can be used from multiple threads.

.. code-block:: python

   import threading
   from concurrent.futures import ThreadPoolExecutor
   
   htm = HTMCore("./data")
   
   def worker(thread_id):
       embedding = np.random.float32(768)
       htm.store_embedding(f"thread_{thread_id}", embedding, {})
   
   # Use from multiple threads
   with ThreadPoolExecutor(max_workers=4) as executor:
       futures = [executor.submit(worker, i) for i in range(10)]
       for future in futures:
           future.result()

Configuration
-------------

Configure the FFI layer for optimal performance.

.. code-block:: python

   from anam_py import configure_ffi
   
   # Configure global settings
   configure_ffi({
       "thread_pool_size": 8,
       "memory_limit_mb": 2048,
       "enable_logging": True,
       "log_level": "INFO",
       "cache_size_mb": 512,
   })

See Also
--------

* :doc:`cbc_core_api` - Rust Core API
* :doc:`tensor_mem_ai_api` - High-level Python library
* :doc:`examples` - Usage examples