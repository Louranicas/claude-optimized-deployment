.. CODE MCP API documentation master file

Claude-Optimized Deployment Engine (CODE) MCP API Documentation
================================================================

Welcome to the comprehensive API documentation for the Claude-Optimized Deployment Engine (CODE). 
This documentation covers all Model Context Protocol (MCP) tools for infrastructure automation, 
monitoring, security, and team communication.

.. toctree::
   :maxdepth: 2
   :caption: Getting Started

   guides/quick_start_guide
   guides/authentication_guide
   guides/integration_patterns

.. toctree::
   :maxdepth: 2
   :caption: API Reference

   reference/cbc_core_api
   reference/python_ffi_api
   reference/tensor_mem_ai_api
   reference/grpc_api
   reference/mcp_tools_reference
   reference/openapi_specification
   reference/error_codes

.. toctree::
   :maxdepth: 2
   :caption: Developer Resources

   examples/api_examples
   examples/deployment_examples
   examples/monitoring_examples
   examples/security_examples
   postman/postman_collection
   sdks/python_sdk
   sdks/typescript_sdk

.. toctree::
   :maxdepth: 2
   :caption: API Documentation

   api/mcp_servers
   api/mcp_tools
   api/mcp_protocols

Overview
--------

The CBC (Code Base Crawler) API ecosystem provides comprehensive programmatic access to:

* **HTM Storage** - High-performance tensor-based storage and semantic search
* **NAM/ANAM Validation** - Ethical and operational validation with 67 axioms (Λ01-Λ67)
* **Tool System** - Extensible tool registry and execution framework
* **Multi-Agent Coordination** - Advanced agent orchestration capabilities
* **Memory Management** - Intelligent memory optimization and garbage collection
* **Code Analysis** - Advanced AST parsing, complexity analysis, and pattern detection
* **Security Framework** - Comprehensive security auditing and access control

Key Features
------------

* **Multi-Language Support** - Rust core with Python FFI and gRPC APIs
* **Advanced Memory Management** - Rust-powered memory optimization
* **Semantic Search** - HTM-based tensor storage and resonance scoring
* **Ethical AI** - NAM/ANAM axiom validation system
* **Async/Await Support** - Full async compatibility across all APIs
* **Tool Chaining** - Advanced tool composition and workflow automation
* **Multi-Agent Systems** - Sophisticated agent coordination capabilities
* **High Performance** - Memory-mapped storage and efficient serialization

Quick Example
-------------

**TensorMem AI (Python):**

.. code-block:: python

   from tensor_mem_ai import TensorMemAgent, create_agent
   from anam_py import HTMCore, AxiomValidator
   import numpy as np

   # Create agent with HTM storage
   agent = create_agent("code_analyzer")
   htm = HTMCore("./storage", shard_count=4)
   validator = AxiomValidator()

   # Register analysis tool
   def analyze_complexity(code):
       return {"complexity": len(code.split()), "functions": code.count("def ")}

   agent.register_tool("analyze", analyze_complexity)

   # Execute analysis
   result = agent.execute_tool("analyze", {"code": "def hello(): return 'world'"})
   print(f"Analysis: {result['result']}")

   # Store in HTM with semantic embedding
   embedding = np.random.float32(768)
   htm.store_embedding("example.py", embedding, {"language": "python"})

   # Validate with NAM axioms
   validation = validator.validate_axiom("AX_NO_HARM", ["AX_BENEFICENCE"])
   print(f"NAM compliant: {validation['is_valid']}")

**Rust Core:**

.. code-block:: rust

   use cbc_core::htm::HTMCore;
   use cbc_core::tools::{ToolRegistry, FileSystemCrawler};
   use nam_core::axioms::AxiomValidator;

   #[tokio::main]
   async fn main() -> Result<(), Box<dyn std::error::Error>> {
       // Initialize HTM storage
       let htm = HTMCore::new("./storage")?;
       
       // Setup tool registry
       let mut registry = ToolRegistry::new();
       registry.register(FileSystemCrawler::new());
       
       // Validate operations with NAM
       let validator = AxiomValidator::new();
       let result = validator.validate_axiom("AX_NO_HARM", &[])?;
       
       println!("NAM validation: {}", result.is_valid);
       Ok(())
   }

API Layers
----------

1. **CBC Core (Rust)** - High-performance core with HTM storage and NAM validation
2. **Python FFI (anam_py)** - Direct Python bindings with NumPy integration
3. **TensorMem AI** - High-level Python library with multi-agent support
4. **gRPC API** - Language-agnostic service interface
5. **REST Gateway** - HTTP/JSON API layer (via FastAPI integration)

Core Components
---------------

* **HTM Storage** - Hybrid Tensor Memory for embeddings and semantic search
* **NAM/ANAM System** - 67 axioms (Λ01-Λ67) for ethical validation
* **Tool System** - Extensible tool registry and execution framework
* **Security Framework** - Comprehensive auditing and access control
* **Multi-Agent Coordination** - Advanced agent orchestration capabilities

Getting Help
------------

* **GitHub Issues**: https://github.com/claude-optimized-deployment/code/issues
* **Community Forum**: https://forum.code-deployment.com
* **Slack Channel**: #code-deployment
* **Email Support**: support@code-deployment.com

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`