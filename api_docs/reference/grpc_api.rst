gRPC API Reference
==================

The CBC (Code Base Crawler) gRPC API provides high-performance, language-agnostic access to all core functionality including crawling, HTM storage, tool execution, and health monitoring.

.. contents:: Table of Contents
   :local:

Overview
--------

The gRPC API is defined in Protocol Buffers and provides:

* **Streaming Operations** - Efficient streaming for large crawling operations
* **Language Agnostic** - Use from any language with gRPC support
* **High Performance** - Binary protocol with efficient serialization
* **Type Safety** - Strongly typed interfaces with auto-generated clients
* **Authentication** - Built-in authentication and authorization support

Service Definition
------------------

The main service interface is defined in ``cbc.proto``:

.. code-block:: protobuf

   syntax = "proto3";
   
   package cbc.api.v1;
   
   service CodeBaseCrawler {
       // Core crawling operations
       rpc CrawlDirectory(CrawlRequest) returns (stream CrawlResponse);
       rpc CrawlGitRepo(GitCrawlRequest) returns (stream CrawlResponse);
       
       // HTM operations
       rpc StoreEmbedding(StoreEmbeddingRequest) returns (StoreResponse);
       rpc QueryByResonance(ResonanceQueryRequest) returns (QueryResponse);
       
       // Tool execution
       rpc ExecuteTool(ToolExecutionRequest) returns (ToolExecutionResponse);
       rpc ListTools(Empty) returns (ToolListResponse);
       
       // Health and monitoring
       rpc HealthCheck(Empty) returns (HealthStatus);
       rpc GetMetrics(Empty) returns (MetricsResponse);
   }

Core Messages
-------------

Request/Response Types
^^^^^^^^^^^^^^^^^^^^^^

**CrawlRequest:**

.. code-block:: protobuf

   message CrawlRequest {
       string path = 1;
       repeated string include_patterns = 2;
       repeated string exclude_patterns = 3;
       CrawlOptions options = 4;
   }
   
   message CrawlOptions {
       bool follow_symlinks = 1;
       bool extract_embeddings = 2;
       bool track_diffs = 3;
       int32 max_depth = 4;
   }

**CrawlResponse:**

.. code-block:: protobuf

   message CrawlResponse {
       string file_path = 1;
       string content_hash = 2;
       Embedding embedding = 3;
       FileMetadata metadata = 4;
       float resonance_score = 5;
   }

**Data Types:**

.. code-block:: protobuf

   message Embedding {
       repeated float values = 1;
       int32 dimensions = 2;
       string model_version = 3;
   }
   
   message FileMetadata {
       string language = 1;
       int32 line_count = 2;
       float complexity_score = 3;
       repeated string dependencies = 4;
       repeated string semantic_tags = 5;
   }

Service Operations
------------------

Directory Crawling
^^^^^^^^^^^^^^^^^^

**CrawlDirectory** - Stream crawl results for directory analysis:

.. code-block:: protobuf

   rpc CrawlDirectory(CrawlRequest) returns (stream CrawlResponse);

**Parameters:**

* ``path`` - Directory path to crawl
* ``include_patterns`` - File patterns to include (e.g., "*.py", "*.rs")
* ``exclude_patterns`` - File patterns to exclude (e.g., "*test*", "*.tmp")
* ``options`` - Crawling configuration options

**Example Usage (Python):**

.. code-block:: python

   import grpc
   from cbc_api.v1 import cbc_pb2, cbc_pb2_grpc
   
   # Create gRPC channel and stub
   channel = grpc.insecure_channel('localhost:50051')
   stub = cbc_pb2_grpc.CodeBaseCrawlerStub(channel)
   
   # Create crawl request
   request = cbc_pb2.CrawlRequest(
       path="/path/to/code",
       include_patterns=["*.py", "*.rs"],
       exclude_patterns=["*test*", "*__pycache__*"],
       options=cbc_pb2.CrawlOptions(
           follow_symlinks=False,
           extract_embeddings=True,
           track_diffs=True,
           max_depth=10
       )
   )
   
   # Stream crawl results
   for response in stub.CrawlDirectory(request):
       print(f"File: {response.file_path}")
       print(f"Language: {response.metadata.language}")
       print(f"Lines: {response.metadata.line_count}")
       print(f"Complexity: {response.metadata.complexity_score:.2f}")
       print(f"Resonance: {response.resonance_score:.3f}")
       print(f"Dependencies: {list(response.metadata.dependencies)}")
       print("---")

**Example Usage (Rust):**

.. code-block:: rust

   use tonic::{transport::Channel, Request};
   use cbc_api::code_base_crawler_client::CodeBaseCrawlerClient;
   use cbc_api::{CrawlRequest, CrawlOptions};
   
   #[tokio::main]
   async fn main() -> Result<(), Box<dyn std::error::Error>> {
       // Connect to server
       let channel = Channel::from_static("http://localhost:50051").connect().await?;
       let mut client = CodeBaseCrawlerClient::new(channel);
       
       // Create request
       let request = Request::new(CrawlRequest {
           path: "/path/to/code".to_string(),
           include_patterns: vec!["*.rs".to_string(), "*.toml".to_string()],
           exclude_patterns: vec!["target/*".to_string()],
           options: Some(CrawlOptions {
               follow_symlinks: false,
               extract_embeddings: true,
               track_diffs: true,
               max_depth: 5,
           }),
       });
       
       // Stream responses
       let mut stream = client.crawl_directory(request).await?.into_inner();
       
       while let Some(response) = stream.message().await? {
           println!("File: {}", response.file_path);
           if let Some(metadata) = response.metadata {
               println!("Language: {}", metadata.language);
               println!("Lines: {}", metadata.line_count);
               println!("Complexity: {:.2}", metadata.complexity_score);
           }
           println!("Resonance: {:.3}", response.resonance_score);
       }
       
       Ok(())
   }

Git Repository Crawling
^^^^^^^^^^^^^^^^^^^^^^^

**CrawlGitRepo** - Stream crawl results for Git repository analysis:

.. code-block:: protobuf

   message GitCrawlRequest {
       string repository_url = 1;
       string branch = 2;
       string commit_hash = 3;
       repeated string include_patterns = 4;
       repeated string exclude_patterns = 5;
       CrawlOptions options = 6;
   }
   
   rpc CrawlGitRepo(GitCrawlRequest) returns (stream CrawlResponse);

**Example Usage (Python):**

.. code-block:: python

   # Create Git crawl request
   git_request = cbc_pb2.GitCrawlRequest(
       repository_url="https://github.com/user/repo.git",
       branch="main",
       include_patterns=["*.py"],
       exclude_patterns=["*test*"],
       options=cbc_pb2.CrawlOptions(
           extract_embeddings=True,
           track_diffs=True
       )
   )
   
   # Stream Git crawl results
   for response in stub.CrawlGitRepo(git_request):
       print(f"Git file: {response.file_path}")
       print(f"Hash: {response.content_hash}")

HTM Storage Operations
^^^^^^^^^^^^^^^^^^^^^^

**StoreEmbedding** - Store embedding with metadata:

.. code-block:: protobuf

   message StoreEmbeddingRequest {
       string key = 1;
       Embedding embedding = 2;
       FileMetadata metadata = 3;
       repeated DiffOperation diff_ops = 4;
   }
   
   message StoreResponse {
       bool success = 1;
       string message = 2;
       string storage_id = 3;
   }
   
   rpc StoreEmbedding(StoreEmbeddingRequest) returns (StoreResponse);

**Example Usage (Python):**

.. code-block:: python

   import numpy as np
   
   # Create embedding (768-dimensional)
   embedding_values = np.random.float32(768).tolist()
   
   # Create store request
   store_request = cbc_pb2.StoreEmbeddingRequest(
       key="src/main.py",
       embedding=cbc_pb2.Embedding(
           values=embedding_values,
           dimensions=768,
           model_version="ada-002"
       ),
       metadata=cbc_pb2.FileMetadata(
           language="python",
           line_count=150,
           complexity_score=45.7,
           dependencies=["numpy", "torch", "pandas"],
           semantic_tags=["machine_learning", "data_processing"]
       )
   )
   
   # Store embedding
   store_response = stub.StoreEmbedding(store_request)
   print(f"Storage success: {store_response.success}")
   print(f"Storage ID: {store_response.storage_id}")

**QueryByResonance** - Query embeddings by resonance threshold:

.. code-block:: protobuf

   message ResonanceQueryRequest {
       Embedding query_embedding = 1;
       float min_resonance = 2;
       int32 max_results = 3;
   }
   
   message QueryResponse {
       repeated QueryResult results = 1;
       float query_time_ms = 2;
   }
   
   message QueryResult {
       string file_path = 1;
       float resonance_score = 2;
       FileMetadata metadata = 3;
   }
   
   rpc QueryByResonance(ResonanceQueryRequest) returns (QueryResponse);

**Example Usage (Python):**

.. code-block:: python

   # Create query embedding
   query_values = np.random.float32(768).tolist()
   
   # Create resonance query
   resonance_request = cbc_pb2.ResonanceQueryRequest(
       query_embedding=cbc_pb2.Embedding(
           values=query_values,
           dimensions=768,
           model_version="ada-002"
       ),
       min_resonance=0.75,
       max_results=10
   )
   
   # Execute query
   query_response = stub.QueryByResonance(resonance_request)
   
   print(f"Query time: {query_response.query_time_ms:.2f}ms")
   print(f"Results found: {len(query_response.results)}")
   
   for result in query_response.results:
       print(f"File: {result.file_path}")
       print(f"Resonance: {result.resonance_score:.3f}")
       print(f"Language: {result.metadata.language}")

Tool Execution
^^^^^^^^^^^^^^

**ExecuteTool** - Execute registered tools:

.. code-block:: protobuf

   message ToolExecutionRequest {
       string tool_name = 1;
       map<string, string> arguments = 2;
       ToolExecutionOptions options = 3;
   }
   
   message ToolExecutionOptions {
       float timeout_seconds = 1;
       int32 memory_limit_mb = 2;
       bool capture_output = 3;
   }
   
   message ToolExecutionResponse {
       bool success = 1;
       string output = 2;
       string error = 3;
       float execution_time_ms = 4;
       int32 memory_used_mb = 5;
   }
   
   rpc ExecuteTool(ToolExecutionRequest) returns (ToolExecutionResponse);

**Example Usage (Python):**

.. code-block:: python

   # Execute filesystem crawler tool
   tool_request = cbc_pb2.ToolExecutionRequest(
       tool_name="filesystem_crawler",
       arguments={
           "path": "/path/to/analyze",
           "pattern": "*.py",
           "recursive": "true"
       },
       options=cbc_pb2.ToolExecutionOptions(
           timeout_seconds=60.0,
           memory_limit_mb=512,
           capture_output=True
       )
   )
   
   # Execute tool
   tool_response = stub.ExecuteTool(tool_request)
   
   if tool_response.success:
       print(f"Tool output: {tool_response.output}")
       print(f"Execution time: {tool_response.execution_time_ms:.2f}ms")
       print(f"Memory used: {tool_response.memory_used_mb}MB")
   else:
       print(f"Tool failed: {tool_response.error}")

**ListTools** - Get available tools:

.. code-block:: protobuf

   message ToolListResponse {
       repeated ToolInfo tools = 1;
   }
   
   message ToolInfo {
       string name = 1;
       string description = 2;
       repeated string input_types = 3;
       map<string, string> metadata = 4;
   }
   
   rpc ListTools(Empty) returns (ToolListResponse);

**Example Usage (Python):**

.. code-block:: python

   # List available tools
   tools_response = stub.ListTools(cbc_pb2.Empty())
   
   print("Available tools:")
   for tool in tools_response.tools:
       print(f"  {tool.name}: {tool.description}")
       print(f"    Input types: {list(tool.input_types)}")
       print(f"    Metadata: {dict(tool.metadata)}")

Health and Monitoring
^^^^^^^^^^^^^^^^^^^^^

**HealthCheck** - Get service health status:

.. code-block:: protobuf

   message HealthStatus {
       bool healthy = 1;
       string version = 2;
       float uptime_seconds = 3;
       map<string, bool> component_status = 4;
   }
   
   rpc HealthCheck(Empty) returns (HealthStatus);

**Example Usage (Python):**

.. code-block:: python

   # Check service health
   health_response = stub.HealthCheck(cbc_pb2.Empty())
   
   print(f"Service healthy: {health_response.healthy}")
   print(f"Version: {health_response.version}")
   print(f"Uptime: {health_response.uptime_seconds:.2f} seconds")
   
   print("Component status:")
   for component, status in health_response.component_status.items():
       print(f"  {component}: {'OK' if status else 'FAILED'}")

**GetMetrics** - Get detailed performance metrics:

.. code-block:: protobuf

   message MetricsResponse {
       map<string, float> metrics = 1;
       int64 timestamp = 2;
   }
   
   rpc GetMetrics(Empty) returns (MetricsResponse);

**Example Usage (Python):**

.. code-block:: python

   # Get performance metrics
   metrics_response = stub.GetMetrics(cbc_pb2.Empty())
   
   print(f"Metrics timestamp: {metrics_response.timestamp}")
   print("Performance metrics:")
   for metric_name, value in metrics_response.metrics.items():
       print(f"  {metric_name}: {value}")

Client Examples
---------------

Python Client
^^^^^^^^^^^^^

Complete Python client example:

.. code-block:: python

   import grpc
   import asyncio
   import numpy as np
   from cbc_api.v1 import cbc_pb2, cbc_pb2_grpc
   
   class CBCClient:
       def __init__(self, server_address="localhost:50051"):
           self.channel = grpc.insecure_channel(server_address)
           self.stub = cbc_pb2_grpc.CodeBaseCrawlerStub(self.channel)
       
       def crawl_directory(self, path, include_patterns=None, exclude_patterns=None):
           """Crawl directory and return results."""
           request = cbc_pb2.CrawlRequest(
               path=path,
               include_patterns=include_patterns or [],
               exclude_patterns=exclude_patterns or [],
               options=cbc_pb2.CrawlOptions(
                   extract_embeddings=True,
                   track_diffs=True
               )
           )
           
           results = []
           for response in self.stub.CrawlDirectory(request):
               results.append({
                   'path': response.file_path,
                   'hash': response.content_hash,
                   'metadata': {
                       'language': response.metadata.language,
                       'lines': response.metadata.line_count,
                       'complexity': response.metadata.complexity_score,
                       'dependencies': list(response.metadata.dependencies)
                   },
                   'resonance': response.resonance_score
               })
           
           return results
       
       def store_embedding(self, key, embedding, metadata):
           """Store embedding with metadata."""
           request = cbc_pb2.StoreEmbeddingRequest(
               key=key,
               embedding=cbc_pb2.Embedding(
                   values=embedding.tolist(),
                   dimensions=len(embedding),
                   model_version="ada-002"
               ),
               metadata=cbc_pb2.FileMetadata(**metadata)
           )
           
           response = self.stub.StoreEmbedding(request)
           return response.success, response.storage_id
       
       def query_similar(self, query_embedding, min_resonance=0.5, max_results=10):
           """Query for similar embeddings."""
           request = cbc_pb2.ResonanceQueryRequest(
               query_embedding=cbc_pb2.Embedding(
                   values=query_embedding.tolist(),
                   dimensions=len(query_embedding)
               ),
               min_resonance=min_resonance,
               max_results=max_results
           )
           
           response = self.stub.QueryByResonance(request)
           
           results = []
           for result in response.results:
               results.append({
                   'path': result.file_path,
                   'resonance': result.resonance_score,
                   'metadata': {
                       'language': result.metadata.language,
                       'lines': result.metadata.line_count
                   }
               })
           
           return results, response.query_time_ms
       
       def execute_tool(self, tool_name, arguments, timeout=30.0):
           """Execute a tool."""
           request = cbc_pb2.ToolExecutionRequest(
               tool_name=tool_name,
               arguments=arguments,
               options=cbc_pb2.ToolExecutionOptions(
                   timeout_seconds=timeout,
                   memory_limit_mb=512,
                   capture_output=True
               )
           )
           
           response = self.stub.ExecuteTool(request)
           return {
               'success': response.success,
               'output': response.output,
               'error': response.error,
               'execution_time': response.execution_time_ms,
               'memory_used': response.memory_used_mb
           }
       
       def get_health(self):
           """Get service health."""
           response = self.stub.HealthCheck(cbc_pb2.Empty())
           return {
               'healthy': response.healthy,
               'version': response.version,
               'uptime': response.uptime_seconds,
               'components': dict(response.component_status)
           }
       
       def close(self):
           """Close client connection."""
           self.channel.close()
   
   # Usage example
   if __name__ == "__main__":
       client = CBCClient()
       
       try:
           # Check health
           health = client.get_health()
           print(f"Service healthy: {health['healthy']}")
           
           # Crawl directory
           results = client.crawl_directory(
               "/path/to/code",
               include_patterns=["*.py"],
               exclude_patterns=["*test*"]
           )
           print(f"Crawled {len(results)} files")
           
           # Store and query embeddings
           embedding = np.random.float32(768)
           success, storage_id = client.store_embedding(
               "example.py",
               embedding,
               {"language": "python", "line_count": 100, "complexity_score": 25.5}
           )
           
           if success:
               similar, query_time = client.query_similar(embedding, min_resonance=0.7)
               print(f"Found {len(similar)} similar files in {query_time:.2f}ms")
           
       finally:
           client.close()

Rust Client
^^^^^^^^^^^

Complete Rust client example:

.. code-block:: rust

   use tonic::{transport::Channel, Request};
   use cbc_api::code_base_crawler_client::CodeBaseCrawlerClient;
   use cbc_api::{
       CrawlRequest, CrawlOptions, StoreEmbeddingRequest, Embedding,
       FileMetadata, ResonanceQueryRequest, ToolExecutionRequest,
       ToolExecutionOptions, Empty
   };
   
   pub struct CBCClient {
       client: CodeBaseCrawlerClient<Channel>,
   }
   
   impl CBCClient {
       pub async fn new(server_address: &str) -> Result<Self, Box<dyn std::error::Error>> {
           let channel = Channel::from_shared(server_address)?
               .connect()
               .await?;
           
           let client = CodeBaseCrawlerClient::new(channel);
           
           Ok(Self { client })
       }
       
       pub async fn crawl_directory(
           &mut self,
           path: &str,
           include_patterns: Vec<String>,
           exclude_patterns: Vec<String>,
       ) -> Result<Vec<cbc_api::CrawlResponse>, Box<dyn std::error::Error>> {
           let request = Request::new(CrawlRequest {
               path: path.to_string(),
               include_patterns,
               exclude_patterns,
               options: Some(CrawlOptions {
                   follow_symlinks: false,
                   extract_embeddings: true,
                   track_diffs: true,
                   max_depth: 10,
               }),
           });
           
           let mut stream = self.client.crawl_directory(request).await?.into_inner();
           let mut results = Vec::new();
           
           while let Some(response) = stream.message().await? {
               results.push(response);
           }
           
           Ok(results)
       }
       
       pub async fn store_embedding(
           &mut self,
           key: &str,
           embedding_values: Vec<f32>,
           metadata: FileMetadata,
       ) -> Result<String, Box<dyn std::error::Error>> {
           let request = Request::new(StoreEmbeddingRequest {
               key: key.to_string(),
               embedding: Some(Embedding {
                   values: embedding_values,
                   dimensions: 768,
                   model_version: "ada-002".to_string(),
               }),
               metadata: Some(metadata),
               diff_ops: vec![],
           });
           
           let response = self.client.store_embedding(request).await?;
           Ok(response.into_inner().storage_id)
       }
       
       pub async fn query_similar(
           &mut self,
           query_embedding: Vec<f32>,
           min_resonance: f32,
           max_results: i32,
       ) -> Result<(Vec<cbc_api::QueryResult>, f32), Box<dyn std::error::Error>> {
           let request = Request::new(ResonanceQueryRequest {
               query_embedding: Some(Embedding {
                   values: query_embedding,
                   dimensions: 768,
                   model_version: "ada-002".to_string(),
               }),
               min_resonance,
               max_results,
           });
           
           let response = self.client.query_by_resonance(request).await?.into_inner();
           Ok((response.results, response.query_time_ms))
       }
       
       pub async fn execute_tool(
           &mut self,
           tool_name: &str,
           arguments: std::collections::HashMap<String, String>,
       ) -> Result<cbc_api::ToolExecutionResponse, Box<dyn std::error::Error>> {
           let request = Request::new(ToolExecutionRequest {
               tool_name: tool_name.to_string(),
               arguments,
               options: Some(ToolExecutionOptions {
                   timeout_seconds: 30.0,
                   memory_limit_mb: 512,
                   capture_output: true,
               }),
           });
           
           let response = self.client.execute_tool(request).await?;
           Ok(response.into_inner())
       }
       
       pub async fn get_health(&mut self) -> Result<cbc_api::HealthStatus, Box<dyn std::error::Error>> {
           let request = Request::new(Empty {});
           let response = self.client.health_check(request).await?;
           Ok(response.into_inner())
       }
   }
   
   #[tokio::main]
   async fn main() -> Result<(), Box<dyn std::error::Error>> {
       let mut client = CBCClient::new("http://localhost:50051").await?;
       
       // Check health
       let health = client.get_health().await?;
       println!("Service healthy: {}", health.healthy);
       
       // Crawl directory
       let results = client
           .crawl_directory(
               "/path/to/code",
               vec!["*.rs".to_string()],
               vec!["target/*".to_string()],
           )
           .await?;
       
       println!("Crawled {} files", results.len());
       
       for result in results.iter().take(5) {
           println!("File: {}", result.file_path);
           if let Some(metadata) = &result.metadata {
               println!("  Language: {}", metadata.language);
               println!("  Lines: {}", metadata.line_count);
           }
       }
       
       Ok(())
   }

Server Configuration
--------------------

Starting the gRPC Server
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: rust

   use cbc_api::run_server;
   
   #[tokio::main]
   async fn main() -> Result<(), Box<dyn std::error::Error>> {
       // Configure logging
       env_logger::init();
       
       // Start gRPC server
       println!("Starting CBC gRPC server on [::1]:50051");
       run_server().await?;
       
       Ok(())
   }

Server Configuration Options
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: toml

   # config.toml
   [server]
   address = "[::1]:50051"
   max_concurrent_streams = 100
   keepalive_time = 30
   keepalive_timeout = 5
   
   [storage]
   htm_path = "./data/htm"
   shard_count = 8
   cache_size_mb = 512
   
   [tools]
   max_execution_time = 300
   memory_limit_mb = 1024
   enable_sandbox = true

Authentication
^^^^^^^^^^^^^^

The gRPC server supports various authentication methods:

.. code-block:: python

   import grpc
   from grpc import ssl_channel_credentials, access_token_call_credentials
   
   # TLS with token authentication
   credentials = ssl_channel_credentials()
   token_credentials = access_token_call_credentials("your-api-token")
   
   # Combine credentials
   composite_credentials = grpc.composite_channel_credentials(
       credentials,
       token_credentials
   )
   
   # Create authenticated channel
   channel = grpc.secure_channel('api.example.com:443', composite_credentials)
   stub = cbc_pb2_grpc.CodeBaseCrawlerStub(channel)

Error Handling
--------------

gRPC Status Codes
^^^^^^^^^^^^^^^^^

Common status codes returned by the API:

* ``OK`` (0) - Success
* ``INVALID_ARGUMENT`` (3) - Invalid request parameters
* ``NOT_FOUND`` (5) - Resource not found
* ``PERMISSION_DENIED`` (7) - Insufficient permissions
* ``RESOURCE_EXHAUSTED`` (8) - Rate limit exceeded
* ``FAILED_PRECONDITION`` (9) - System not ready
* ``INTERNAL`` (13) - Internal server error
* ``UNAVAILABLE`` (14) - Service unavailable

**Error Handling Example:**

.. code-block:: python

   import grpc
   
   try:
       response = stub.CrawlDirectory(request)
       for result in response:
           print(f"File: {result.file_path}")
   except grpc.RpcError as e:
       if e.code() == grpc.StatusCode.INVALID_ARGUMENT:
           print(f"Invalid request: {e.details()}")
       elif e.code() == grpc.StatusCode.NOT_FOUND:
           print(f"Path not found: {e.details()}")
       elif e.code() == grpc.StatusCode.PERMISSION_DENIED:
           print(f"Permission denied: {e.details()}")
       else:
           print(f"RPC failed: {e.code()} - {e.details()}")

Performance Considerations
--------------------------

* **Streaming** - Use streaming RPCs for large operations
* **Batch Operations** - Group multiple requests when possible
* **Connection Pooling** - Reuse gRPC channels
* **Compression** - Enable gzip compression for large payloads
* **Timeouts** - Set appropriate timeouts for operations
* **Keepalive** - Configure keepalive for long-lived connections

See Also
--------

* :doc:`cbc_core_api` - Rust Core API
* :doc:`python_ffi_api` - Python FFI bindings  
* :doc:`tensor_mem_ai_api` - High-level Python library
* `gRPC Documentation <https://grpc.io/docs/>`_ - Official gRPC documentation