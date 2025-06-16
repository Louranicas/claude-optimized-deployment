# CBC API Documentation

Comprehensive API documentation for the Code Base Crawler (CBC) system.

## Overview

The CBC API ecosystem provides multi-layered access to advanced code analysis capabilities:

- **CBC Core (Rust)** - High-performance core with HTM storage and NAM validation
- **Python FFI (anam_py)** - Direct Python bindings with NumPy integration  
- **TensorMem AI** - High-level Python library with multi-agent support
- **gRPC API** - Language-agnostic service interface
- **REST Gateway** - HTTP/JSON API layer

## Quick Start

### Python (TensorMem AI)

```python
from tensor_mem_ai import TensorMemAgent, create_agent
from anam_py import HTMCore, AxiomValidator

# Create agent with HTM storage
agent = create_agent("analyzer")
htm = HTMCore("./storage")
validator = AxiomValidator()

# Analyze code
result = agent.execute_tool("analyze", {"code": "def hello(): return 'world'"})
print(f"Analysis: {result['result']}")
```

### Rust Core

```rust
use cbc_core::htm::HTMCore;
use nam_core::axioms::AxiomValidator;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let htm = HTMCore::new("./storage")?;
    let validator = AxiomValidator::new();
    
    let result = validator.validate_axiom("AX_NO_HARM", &[])?;
    println!("NAM valid: {}", result.is_valid);
    Ok(())
}
```

### gRPC (Python)

```python
import grpc
from cbc_api.v1 import cbc_pb2_grpc

channel = grpc.insecure_channel('localhost:50051')
stub = cbc_pb2_grpc.CodeBaseCrawlerStub(channel)

# Check health
health = stub.HealthCheck(cbc_pb2.Empty())
print(f"Server healthy: {health.healthy}")
```

## Documentation Structure

```
api_docs/
├── reference/           # API Reference Documentation
│   ├── cbc_core_api.rst        # Rust Core API
│   ├── python_ffi_api.rst      # Python FFI bindings
│   ├── tensor_mem_ai_api.rst   # TensorMem AI library
│   └── grpc_api.rst            # gRPC service definitions
├── examples/            # Usage Examples
│   └── api_examples.rst        # Comprehensive examples
├── openapi/            # OpenAPI/Swagger Specifications
│   └── cbc_openapi.yaml        # REST API specification
├── guides/             # Integration Guides
├── conf.py             # Sphinx configuration
└── index.rst           # Main documentation index
```

## Key Features

- **HTM Storage** - Hybrid Tensor Memory for semantic search
- **NAM/ANAM System** - 67 axioms (Λ01-Λ67) for ethical validation
- **Multi-Agent Coordination** - Advanced agent orchestration
- **Tool System** - Extensible tool registry and execution
- **Security Framework** - Comprehensive auditing and access control
- **Memory Management** - Rust-powered memory optimization

## Building Documentation

```bash
# Install dependencies
pip install sphinx sphinx-rtd-theme sphinxcontrib-openapi myst-parser

# Build HTML documentation
cd api_docs
make html

# Serve locally
python -m http.server 8000 -d _build/html
```

## API Layers

1. **CBC Core (Rust)** - High-performance foundation
2. **Python FFI** - Direct Rust bindings for Python
3. **TensorMem AI** - High-level Python library
4. **gRPC Service** - Language-agnostic API
5. **REST Gateway** - HTTP/JSON interface

## Core Components

### HTM Storage
- 768-dimensional embeddings
- Sharded storage for performance
- Semantic similarity search
- Resonance-based querying

### NAM/ANAM Validation
- 67 axioms across 7 categories
- Ethical tension calculation
- Resonance score validation
- Batch validation support

### Tool System
- Extensible tool registry
- Async execution support
- Resource management
- Tool chaining capabilities

### Multi-Agent Coordination
- Agent registration and discovery
- Task delegation and broadcasting
- Consensus mechanisms
- Performance monitoring

## Getting Started

1. **Choose Your API Layer**
   - Use TensorMem AI for high-level Python development
   - Use CBC Core for maximum performance in Rust
   - Use gRPC for language-agnostic integration
   - Use REST API for web applications

2. **Install Dependencies**
   ```bash
   # Python
   pip install tensor-mem-ai anam-py
   
   # Rust
   cargo add cbc-core nam-core
   ```

3. **Initialize Storage**
   ```python
   from anam_py import HTMCore
   htm = HTMCore("./storage", shard_count=4)
   ```

4. **Start Building**
   - Follow the examples in the documentation
   - Check the API reference for detailed method signatures
   - Use the OpenAPI spec for REST integration

## Support

- **GitHub Issues**: [Report bugs and request features](https://github.com/cbc-api/issues)
- **Documentation**: [Full API documentation](https://docs.cbc-api.com)
- **Examples**: See `examples/` directory for usage patterns
- **Community**: [Discord server](https://discord.gg/cbc-api)

## License

MIT License - see LICENSE file for details.