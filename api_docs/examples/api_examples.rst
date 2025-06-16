API Usage Examples
==================

Comprehensive examples demonstrating how to use the CBC API ecosystem across different languages and use cases.

.. contents:: Table of Contents
   :local:

Quick Start Examples
--------------------

Python Quick Start
^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from tensor_mem_ai import TensorMemAgent, create_agent
   import numpy as np
   
   # Create agent with automatic setup
   agent = create_agent("my_agent")
   
   # Register a simple tool
   def analyze_code(file_path):
       with open(file_path, 'r') as f:
           content = f.read()
       return {
           "lines": len(content.splitlines()),
           "chars": len(content),
           "functions": content.count("def ")
       }
   
   agent.register_tool("analyze_code", analyze_code)
   
   # Execute tool
   result = agent.execute_tool("analyze_code", {"file_path": "main.py"})
   print(f"Analysis: {result['result']}")

Rust Quick Start
^^^^^^^^^^^^^^^^^

.. code-block:: rust

   use cbc_core::htm::HTMCore;
   use cbc_core::tools::{ToolRegistry, FileSystemCrawler};
   use tokio;
   
   #[tokio::main]
   async fn main() -> Result<(), Box<dyn std::error::Error>> {
       // Initialize HTM storage
       let htm = HTMCore::new("./data/htm_storage")?;
       
       // Create tool registry
       let mut registry = ToolRegistry::new();
       registry.register(FileSystemCrawler::new());
       
       // Execute filesystem crawling
       let input = ToolInput {
           id: Uuid::new_v4(),
           input_type: InputType::Directory("./src".to_string()),
           metadata: HashMap::new(),
           priority: Priority::Normal,
       };
       
       let context = Arc::new(ToolContext::new(1024 * 1024 * 1024)); // 1GB limit
       let result = registry.execute_tool("filesystem_crawler", input, context).await?;
       
       println!("Crawling completed: {:?}", result);
       Ok(())
   }

gRPC Quick Start
^^^^^^^^^^^^^^^^

.. code-block:: python

   import grpc
   from cbc_api.v1 import cbc_pb2, cbc_pb2_grpc
   
   # Connect to CBC gRPC server
   channel = grpc.insecure_channel('localhost:50051')
   stub = cbc_pb2_grpc.CodeBaseCrawlerStub(channel)
   
   # Check server health
   health = stub.HealthCheck(cbc_pb2.Empty())
   print(f"Server healthy: {health.healthy}")
   
   # Crawl directory
   request = cbc_pb2.CrawlRequest(
       path="./src",
       include_patterns=["*.py"],
       options=cbc_pb2.CrawlOptions(extract_embeddings=True)
   )
   
   for response in stub.CrawlDirectory(request):
       print(f"File: {response.file_path} (resonance: {response.resonance_score:.3f})")

Advanced Usage Examples
-----------------------

Multi-Agent Code Analysis
^^^^^^^^^^^^^^^^^^^^^^^^^^

This example shows how to set up multiple specialized agents for comprehensive code analysis:

.. code-block:: python

   import asyncio
   from tensor_mem_ai import TensorMemAgent, MultiAgentCoordinator
   from anam_py import HTMCore, AxiomValidator
   import numpy as np
   
   async def advanced_code_analysis():
       # Initialize core systems
       htm = HTMCore("./data/htm_storage", shard_count=8)
       validator = AxiomValidator()
       
       # Create specialized agents
       syntax_agent = TensorMemAgent("syntax_analyzer")
       semantic_agent = TensorMemAgent("semantic_analyzer") 
       quality_agent = TensorMemAgent("quality_checker")
       security_agent = TensorMemAgent("security_auditor")
       
       # Register syntax analysis tools
       def check_syntax(code):
           import ast
           try:
               ast.parse(code)
               return {"valid": True, "errors": []}
           except SyntaxError as e:
               return {"valid": False, "errors": [str(e)]}
       
       syntax_agent.register_tool("check_syntax", check_syntax)
       
       # Register semantic analysis tools
       def extract_semantics(code):
           import ast
           tree = ast.parse(code)
           
           functions = []
           classes = []
           imports = []
           
           for node in ast.walk(tree):
               if isinstance(node, ast.FunctionDef):
                   functions.append({
                       "name": node.name,
                       "args": [arg.arg for arg in node.args.args],
                       "line": node.lineno
                   })
               elif isinstance(node, ast.ClassDef):
                   classes.append({
                       "name": node.name,
                       "methods": [n.name for n in node.body if isinstance(n, ast.FunctionDef)],
                       "line": node.lineno
                   })
               elif isinstance(node, ast.Import):
                   for alias in node.names:
                       imports.append({"module": alias.name, "line": node.lineno})
           
           return {
               "functions": functions,
               "classes": classes,
               "imports": imports,
               "complexity": len(functions) + len(classes) * 2
           }
       
       semantic_agent.register_tool("extract_semantics", extract_semantics)
       
       # Register quality checking tools
       def check_quality(semantics):
           score = 100
           issues = []
           
           # Check function complexity
           if semantics["complexity"] > 20:
               score -= 20
               issues.append("High complexity detected")
           
           # Check naming conventions
           for func in semantics["functions"]:
               if not func["name"].islower():
                   score -= 5
                   issues.append(f"Function {func['name']} doesn't follow naming convention")
           
           return {
               "score": max(0, score),
               "issues": issues,
               "grade": "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "F"
           }
       
       quality_agent.register_tool("check_quality", check_quality)
       
       # Register security auditing tools
       def security_audit(code):
           issues = []
           severity = "low"
           
           # Simple security checks
           dangerous_patterns = ["eval(", "exec(", "subprocess.call", "__import__"]
           for pattern in dangerous_patterns:
               if pattern in code:
                   issues.append(f"Potentially dangerous pattern: {pattern}")
                   severity = "high"
           
           # Check NAM compliance
           action_vector = np.array([len(issues), len(code.split()), code.count("import")])
           result = validator.validate_axiom("AX_NO_HARM", ["AX_BENEFICENCE"])
           
           return {
               "issues": issues,
               "severity": severity,
               "nam_compliant": result["is_valid"],
               "ethical_tension": result["ethical_tension"]
           }
       
       security_agent.register_tool("security_audit", security_audit)
       
       # Create multi-agent coordinator
       coordinator = MultiAgentCoordinator(max_agents=4)
       coordinator.register_agent("syntax", syntax_agent)
       coordinator.register_agent("semantic", semantic_agent)
       coordinator.register_agent("quality", quality_agent)
       coordinator.register_agent("security", security_agent)
       
       # Analyze code file
       code_file = "example.py"
       with open(code_file, 'r') as f:
           code_content = f.read()
       
       print(f"Analyzing {code_file}...")
       
       # Step 1: Syntax analysis
       syntax_result = await coordinator.delegate_task(
           "syntax", 
           "check_syntax", 
           {"code": code_content}
       )
       
       if not syntax_result.output["valid"]:
           print("❌ Syntax errors found:")
           for error in syntax_result.output["errors"]:
               print(f"  - {error}")
           return
       
       print("✅ Syntax check passed")
       
       # Step 2: Semantic analysis
       semantic_result = await coordinator.delegate_task(
           "semantic",
           "extract_semantics",
           {"code": code_content}
       )
       
       semantics = semantic_result.output
       print(f"📊 Code analysis:")
       print(f"  Functions: {len(semantics['functions'])}")
       print(f"  Classes: {len(semantics['classes'])}")
       print(f"  Imports: {len(semantics['imports'])}")
       print(f"  Complexity: {semantics['complexity']}")
       
       # Step 3: Quality assessment
       quality_result = await coordinator.delegate_task(
           "quality",
           "check_quality",
           {"semantics": semantics}
       )
       
       quality = quality_result.output
       print(f"🎯 Quality assessment:")
       print(f"  Score: {quality['score']}/100 (Grade: {quality['grade']})")
       if quality["issues"]:
           print("  Issues:")
           for issue in quality["issues"]:
               print(f"    - {issue}")
       
       # Step 4: Security audit
       security_result = await coordinator.delegate_task(
           "security",
           "security_audit",
           {"code": code_content}
       )
       
       security = security_result.output
       print(f"🔒 Security audit:")
       print(f"  Severity: {security['severity']}")
       print(f"  NAM Compliant: {security['nam_compliant']}")
       print(f"  Ethical tension: {security['ethical_tension']:.3f}")
       
       if security["issues"]:
           print("  Security issues:")
           for issue in security["issues"]:
               print(f"    - {issue}")
       
       # Store analysis in HTM
       analysis_embedding = np.random.float32(768)  # In real use, generate proper embedding
       analysis_metadata = {
           "language": "python",
           "line_count": len(code_content.splitlines()),
           "complexity_score": float(semantics["complexity"]),
           "quality_score": float(quality["score"]),
           "security_level": security["severity"],
           "dependencies": [imp["module"] for imp in semantics["imports"]]
       }
       
       htm.store_embedding(code_file, analysis_embedding, analysis_metadata)
       print(f"📝 Analysis stored in HTM storage")
   
   # Run the analysis
   asyncio.run(advanced_code_analysis())

Real-time Code Monitoring
^^^^^^^^^^^^^^^^^^^^^^^^^^

Monitor a codebase for changes and automatically analyze new/modified files:

.. code-block:: python

   import asyncio
   import time
   from pathlib import Path
   from watchdog.observers import Observer
   from watchdog.events import FileSystemEventHandler
   from tensor_mem_ai import TensorMemAgent, BashTool, FileSystemTool
   from anam_py import HTMCore, CodeBaseCrawler
   
   class CodeMonitor(FileSystemEventHandler):
       def __init__(self, agent, htm_core):
           self.agent = agent
           self.htm_core = htm_core
           self.crawler = CodeBaseCrawler(htm_core)
           
       def on_modified(self, event):
           if event.is_directory:
               return
               
           file_path = event.src_path
           if file_path.endswith(('.py', '.rs', '.js', '.ts')):
               asyncio.create_task(self.analyze_file(file_path))
       
       async def analyze_file(self, file_path):
           print(f"🔍 Analyzing changed file: {file_path}")
           
           try:
               # Extract file analysis
               analysis = self.crawler.analyze_file(file_path)
               
               # Run quality checks
               result = await self.agent.execute_tool_async(
                   "quality_check",
                   {"file_path": file_path, "analysis": analysis}
               )
               
               if result["status"] == "success":
                   quality = result["result"]
                   if quality["score"] < 70:
                       print(f"⚠️  Quality warning for {file_path}: {quality['score']}/100")
                   else:
                       print(f"✅ Quality check passed for {file_path}: {quality['score']}/100")
               
           except Exception as e:
               print(f"❌ Error analyzing {file_path}: {e}")
   
   async def setup_monitoring():
       # Initialize systems
       htm = HTMCore("./monitoring/htm_storage")
       agent = TensorMemAgent("monitor_agent")
       
       # Register quality check tool
       def quality_check(file_path, analysis):
           # Simple quality metrics
           score = 100
           issues = []
           
           if analysis.get("complexity_score", 0) > 50:
               score -= 30
               issues.append("High complexity")
           
           if analysis.get("line_count", 0) > 500:
               score -= 20
               issues.append("File too long")
           
           return {"score": score, "issues": issues}
       
       agent.register_tool("quality_check", quality_check)
       
       # Setup file monitoring
       monitor = CodeMonitor(agent, htm)
       observer = Observer()
       observer.schedule(monitor, path="./src", recursive=True)
       
       print("🚀 Starting code monitoring...")
       observer.start()
       
       try:
           while True:
               await asyncio.sleep(1)
       except KeyboardInterrupt:
           observer.stop()
           print("🛑 Monitoring stopped")
       
       observer.join()
   
   # Run monitoring
   asyncio.run(setup_monitoring())

Distributed Analysis Pipeline
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Scale analysis across multiple workers using gRPC:

.. code-block:: python

   import asyncio
   import grpc
   from concurrent.futures import ThreadPoolExecutor
   from cbc_api.v1 import cbc_pb2, cbc_pb2_grpc
   
   class DistributedAnalyzer:
       def __init__(self, worker_addresses):
           self.workers = []
           for address in worker_addresses:
               channel = grpc.insecure_channel(address)
               stub = cbc_pb2_grpc.CodeBaseCrawlerStub(channel)
               self.workers.append(stub)
       
       async def analyze_repository(self, repo_path, patterns=None):
           """Distribute repository analysis across workers."""
           patterns = patterns or ["*.py", "*.rs", "*.js"]
           
           # Get file list
           import os
           files = []
           for root, dirs, filenames in os.walk(repo_path):
               for filename in filenames:
                   if any(filename.endswith(p.replace("*", "")) for p in patterns):
                       files.append(os.path.join(root, filename))
           
           print(f"📁 Found {len(files)} files to analyze")
           
           # Distribute files across workers
           chunk_size = len(files) // len(self.workers)
           chunks = [files[i:i + chunk_size] for i in range(0, len(files), chunk_size)]
           
           # Analyze chunks in parallel
           tasks = []
           for i, (worker, chunk) in enumerate(zip(self.workers, chunks)):
               task = self.analyze_chunk(worker, chunk, f"worker_{i}")
               tasks.append(task)
           
           results = await asyncio.gather(*tasks)
           
           # Aggregate results
           total_files = sum(len(result) for result in results)
           print(f"✅ Analysis complete: {total_files} files processed")
           
           return results
       
       async def analyze_chunk(self, worker, file_paths, worker_id):
           """Analyze a chunk of files on a specific worker."""
           print(f"🔧 {worker_id} processing {len(file_paths)} files")
           
           results = []
           for file_path in file_paths:
               try:
                   # Use tool execution for analysis
                   request = cbc_pb2.ToolExecutionRequest(
                       tool_name="ast_analyzer",
                       arguments={"file_path": file_path},
                       options=cbc_pb2.ToolExecutionOptions(
                           timeout_seconds=30.0,
                           memory_limit_mb=256
                       )
                   )
                   
                   response = worker.ExecuteTool(request)
                   
                   if response.success:
                       results.append({
                           "file": file_path,
                           "analysis": response.output,
                           "worker": worker_id
                       })
                   else:
                       print(f"❌ Analysis failed for {file_path}: {response.error}")
               
               except Exception as e:
                   print(f"❌ Error processing {file_path}: {e}")
           
           print(f"✅ {worker_id} completed: {len(results)} successful analyses")
           return results
   
   async def main():
       # Setup distributed analyzer with multiple workers
       workers = [
           "localhost:50051",
           "localhost:50052", 
           "localhost:50053",
           "localhost:50054"
       ]
       
       analyzer = DistributedAnalyzer(workers)
       
       # Analyze large repository
       results = await analyzer.analyze_repository("./large_codebase")
       
       # Process aggregated results
       all_analyses = []
       for worker_results in results:
           all_analyses.extend(worker_results)
       
       print(f"📊 Total analyses: {len(all_analyses)}")
       
       # Generate summary statistics
       languages = {}
       total_complexity = 0
       
       for analysis in all_analyses:
           # Parse analysis output (assuming JSON format)
           import json
           try:
               data = json.loads(analysis["analysis"])
               lang = data.get("language", "unknown")
               languages[lang] = languages.get(lang, 0) + 1
               total_complexity += data.get("complexity_score", 0)
           except:
               continue
       
       print("📈 Analysis Summary:")
       print(f"  Languages detected: {languages}")
       print(f"  Average complexity: {total_complexity / len(all_analyses):.2f}")
   
   # Run distributed analysis
   asyncio.run(main())

HTM-Powered Semantic Search
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Build a semantic code search engine using HTM storage:

.. code-block:: python

   import numpy as np
   from anam_py import HTMCore, CodeBaseCrawler, calculate_resonance_score
   from anam_py.kernels import ResonanceKernel
   import torch
   
   class SemanticCodeSearch:
       def __init__(self, storage_path):
           self.htm = HTMCore(storage_path, shard_count=16)
           self.crawler = CodeBaseCrawler(self.htm)
           self.resonance_kernel = ResonanceKernel(n_harmonics=12)
       
       def index_codebase(self, codebase_path):
           """Index entire codebase for semantic search."""
           print(f"🔍 Indexing codebase: {codebase_path}")
           
           # Crawl and extract embeddings
           results = self.crawler.crawl_directory(
               codebase_path,
               include_patterns=["*.py", "*.rs", "*.js", "*.ts"],
               exclude_patterns=["*test*", "*node_modules*", "*target*"],
               extract_embeddings=True
           )
           
           indexed_count = 0
           for result in results:
               if result.get("embedding") is not None:
                   # Store in HTM with enhanced metadata
                   metadata = {
                       **result["metadata"],
                       "indexed_at": "2024-01-01",
                       "search_keywords": self.extract_keywords(result["content"])
                   }
                   
                   self.htm.store_embedding(
                       result["path"],
                       result["embedding"],
                       metadata
                   )
                   indexed_count += 1
           
           print(f"✅ Indexed {indexed_count} files")
           return indexed_count
       
       def extract_keywords(self, content):
           """Extract searchable keywords from code content."""
           import re
           
           # Extract function names
           functions = re.findall(r'def\s+(\w+)', content)
           
           # Extract class names  
           classes = re.findall(r'class\s+(\w+)', content)
           
           # Extract import statements
           imports = re.findall(r'import\s+(\w+)', content)
           imports.extend(re.findall(r'from\s+(\w+)', content))
           
           return functions + classes + imports
       
       def search(self, query, limit=10, min_resonance=0.5):
           """Perform semantic search with resonance scoring."""
           print(f"🔎 Searching for: '{query}'")
           
           # Generate query embedding (simplified - in practice use proper embedding model)
           query_embedding = self.generate_query_embedding(query)
           
           # Search similar embeddings
           similar_files = self.htm.search_similar(
               query_embedding,
               limit=limit * 2,  # Get more for resonance filtering
               min_similarity=0.3
           )
           
           # Calculate resonance scores
           resonance_results = []
           for file_path, similarity, data in similar_files:
               # Calculate resonance using kernel
               file_embedding = torch.tensor(data["embedding"]["values"])
               query_tensor = torch.tensor(query_embedding)
               
               resonance = calculate_resonance_score(
                   file_embedding.unsqueeze(0),
                   self.resonance_kernel,
                   t=1.0
               )
               
               if resonance.value >= min_resonance:
                   resonance_results.append({
                       "file": file_path,
                       "similarity": similarity,
                       "resonance": resonance.value,
                       "nam_compliant": resonance.nam_compliant,
                       "metadata": data["metadata"]
                   })
           
           # Sort by resonance score
           resonance_results.sort(key=lambda x: x["resonance"], reverse=True)
           
           return resonance_results[:limit]
       
       def generate_query_embedding(self, query):
           """Generate embedding for search query."""
           # Simplified embedding generation
           # In practice, use a proper language model
           words = query.lower().split()
           embedding = np.random.float32(768)
           
           # Add some deterministic components based on query
           for i, word in enumerate(words):
               if i < len(embedding):
                   embedding[i] += hash(word) % 100 / 100.0
           
           # Normalize
           embedding = embedding / np.linalg.norm(embedding)
           return embedding
       
       def explain_result(self, result):
           """Explain why a result was returned."""
           explanation = []
           
           explanation.append(f"File: {result['file']}")
           explanation.append(f"Similarity: {result['similarity']:.3f}")
           explanation.append(f"Resonance: {result['resonance']:.3f}")
           explanation.append(f"NAM Compliant: {result['nam_compliant']}")
           
           metadata = result["metadata"]
           explanation.append(f"Language: {metadata.get('language', 'unknown')}")
           explanation.append(f"Complexity: {metadata.get('complexity_score', 0):.2f}")
           
           if "search_keywords" in metadata:
               keywords = metadata["search_keywords"][:5]  # Top 5 keywords
               explanation.append(f"Keywords: {', '.join(keywords)}")
           
           return "\n".join(explanation)
   
   # Usage example
   def demo_semantic_search():
       search_engine = SemanticCodeSearch("./search_index")
       
       # Index codebase
       search_engine.index_codebase("./example_project")
       
       # Perform searches
       queries = [
           "machine learning model training",
           "database connection handling", 
           "error handling and logging",
           "user authentication system",
           "API endpoint definition"
       ]
       
       for query in queries:
           print(f"\n{'='*50}")
           results = search_engine.search(query, limit=5, min_resonance=0.6)
           
           if results:
               print(f"Found {len(results)} results for '{query}':")
               for i, result in enumerate(results, 1):
                   print(f"\n{i}. {search_engine.explain_result(result)}")
           else:
               print(f"No high-resonance results found for '{query}'")
   
   # Run demo
   demo_semantic_search()

Integration Patterns
--------------------

FastAPI Integration
^^^^^^^^^^^^^^^^^^^

Expose CBC functionality through a REST API:

.. code-block:: python

   from fastapi import FastAPI, HTTPException, BackgroundTasks
   from pydantic import BaseModel
   from typing import List, Optional
   from tensor_mem_ai import TensorMemAgent
   from anam_py import HTMCore, AxiomValidator
   import numpy as np
   
   app = FastAPI(title="CBC API Gateway", version="1.0.0")
   
   # Initialize core systems
   htm = HTMCore("./api_storage")
   validator = AxiomValidator()
   agent = TensorMemAgent("api_agent")
   
   # Request/Response models
   class AnalysisRequest(BaseModel):
       code: str
       language: str
       check_quality: bool = True
       check_security: bool = True
   
   class AnalysisResponse(BaseModel):
       success: bool
       analysis: dict
       quality_score: Optional[float]
       security_issues: List[str]
       nam_compliant: bool
   
   class SearchRequest(BaseModel):
       query: str
       limit: int = 10
       min_resonance: float = 0.5
   
   class SearchResult(BaseModel):
       file_path: str
       similarity: float
       resonance: float
       metadata: dict
   
   # Setup tools
   def setup_agent_tools():
       def analyze_code_quality(code, language):
           # Quality analysis implementation
           lines = len(code.splitlines())
           complexity = code.count("if") + code.count("for") + code.count("while")
           
           score = 100
           if lines > 200:
               score -= 20
           if complexity > 10:
               score -= 15
           
           return {"score": score, "lines": lines, "complexity": complexity}
       
       def security_scan(code):
           dangerous_patterns = ["eval(", "exec(", "subprocess", "__import__"]
           issues = [p for p in dangerous_patterns if p in code]
           
           return {"issues": issues, "severity": "high" if issues else "low"}
       
       agent.register_tool("analyze_quality", analyze_code_quality)
       agent.register_tool("security_scan", security_scan)
   
   setup_agent_tools()
   
   @app.post("/analyze", response_model=AnalysisResponse)
   async def analyze_code(request: AnalysisRequest):
       """Analyze code for quality, security, and NAM compliance."""
       try:
           analysis = {"language": request.language}
           quality_score = None
           security_issues = []
           
           # Quality analysis
           if request.check_quality:
               quality_result = await agent.execute_tool_async(
                   "analyze_quality",
                   {"code": request.code, "language": request.language}
               )
               if quality_result["status"] == "success":
                   quality_score = quality_result["result"]["score"]
                   analysis["quality"] = quality_result["result"]
           
           # Security analysis
           if request.check_security:
               security_result = await agent.execute_tool_async(
                   "security_scan",
                   {"code": request.code}
               )
               if security_result["status"] == "success":
                   security_issues = security_result["result"]["issues"]
                   analysis["security"] = security_result["result"]
           
           # NAM compliance check
           action_vector = np.array([len(request.code), len(security_issues)])
           nam_result = validator.validate_axiom("AX_NO_HARM", ["AX_BENEFICENCE"])
           
           return AnalysisResponse(
               success=True,
               analysis=analysis,
               quality_score=quality_score,
               security_issues=security_issues,
               nam_compliant=nam_result["is_valid"]
           )
           
       except Exception as e:
           raise HTTPException(status_code=500, detail=str(e))
   
   @app.post("/search", response_model=List[SearchResult])
   async def semantic_search(request: SearchRequest):
       """Perform semantic search across indexed code."""
       try:
           # Generate query embedding (simplified)
           query_embedding = np.random.float32(768)
           
           # Search HTM storage
           results = htm.search_similar(
               query_embedding,
               limit=request.limit,
               min_similarity=request.min_resonance
           )
           
           search_results = []
           for file_path, similarity, data in results:
               search_results.append(SearchResult(
                   file_path=file_path,
                   similarity=similarity,
                   resonance=similarity,  # Simplified
                   metadata=data.get("metadata", {})
               ))
           
           return search_results
           
       except Exception as e:
           raise HTTPException(status_code=500, detail=str(e))
   
   @app.post("/index")
   async def index_repository(background_tasks: BackgroundTasks, repo_path: str):
       """Index a repository in the background."""
       def index_task():
           # Implementation for background indexing
           pass
       
       background_tasks.add_task(index_task)
       return {"message": "Indexing started", "repo_path": repo_path}
   
   @app.get("/health")
   async def health_check():
       """Health check endpoint."""
       try:
           # Check HTM storage
           stats = htm.get_memory_stats()
           
           # Check agent
           agent_stats = agent.get_memory_stats()
           
           return {
               "status": "healthy",
               "htm_storage": "ok",
               "agent": "ok",
               "memory_usage": {
                   "htm": stats.get("used", 0),
                   "agent": agent_stats.get("total_used", 0)
               }
           }
       except Exception as e:
           raise HTTPException(status_code=503, detail=f"Service unhealthy: {e}")
   
   if __name__ == "__main__":
       import uvicorn
       uvicorn.run(app, host="0.0.0.0", port=8000)

CLI Tool Integration
^^^^^^^^^^^^^^^^^^^^

Create command-line tools using the CBC APIs:

.. code-block:: python

   #!/usr/bin/env python3
   """
   CBC CLI Tool - Command-line interface for Code Base Crawler
   """
   
   import click
   import asyncio
   import json
   from pathlib import Path
   from tensor_mem_ai import TensorMemAgent, BashTool, FileSystemTool
   from anam_py import HTMCore, AxiomValidator, CodeBaseCrawler
   
   @click.group()
   @click.option('--storage', default='./cbc_data', help='HTM storage path')
   @click.option('--verbose', is_flag=True, help='Verbose output')
   @click.pass_context
   def cli(ctx, storage, verbose):
       """CBC - Code Base Crawler CLI Tool"""
       ctx.ensure_object(dict)
       ctx.obj['storage_path'] = storage
       ctx.obj['verbose'] = verbose
       
       # Initialize core systems
       ctx.obj['htm'] = HTMCore(storage, shard_count=4)
       ctx.obj['validator'] = AxiomValidator()
       ctx.obj['agent'] = TensorMemAgent("cli_agent")
   
   @cli.command()
   @click.argument('path', type=click.Path(exists=True))
   @click.option('--patterns', '-p', multiple=True, help='Include patterns')
   @click.option('--exclude', '-e', multiple=True, help='Exclude patterns')
   @click.option('--output', '-o', type=click.File('w'), help='Output JSON file')
   @click.pass_context
   def crawl(ctx, path, patterns, exclude, output):
       """Crawl directory and analyze code files."""
       htm = ctx.obj['htm']
       crawler = CodeBaseCrawler(htm)
       
       if not patterns:
           patterns = ["*.py", "*.rs", "*.js", "*.ts"]
       
       click.echo(f"🔍 Crawling {path}...")
       
       results = crawler.crawl_directory(
           path,
           include_patterns=list(patterns),
           exclude_patterns=list(exclude),
           extract_embeddings=True
       )
       
       click.echo(f"✅ Found {len(results)} files")
       
       if ctx.obj['verbose']:
           for result in results:
               click.echo(f"  📄 {result['path']}")
               click.echo(f"     Language: {result['metadata'].get('language', 'unknown')}")
               click.echo(f"     Lines: {result['metadata'].get('line_count', 0)}")
       
       if output:
           json.dump(results, output, indent=2)
           click.echo(f"📝 Results saved to {output.name}")
   
   @cli.command()
   @click.argument('query')
   @click.option('--limit', '-l', default=10, help='Maximum results')
   @click.option('--min-resonance', '-r', default=0.5, help='Minimum resonance score')
   @click.pass_context
   def search(ctx, query, limit, min_resonance):
       """Search indexed code using semantic similarity."""
       htm = ctx.obj['htm']
       
       click.echo(f"🔎 Searching for: '{query}'")
       
       # Generate query embedding (simplified)
       import numpy as np
       query_embedding = np.random.float32(768)
       
       results = htm.search_similar(
           query_embedding,
           limit=limit,
           min_similarity=min_resonance
       )
       
       if results:
           click.echo(f"📊 Found {len(results)} results:")
           for i, (file_path, similarity, data) in enumerate(results, 1):
               click.echo(f"{i}. {file_path} (similarity: {similarity:.3f})")
               if ctx.obj['verbose']:
                   metadata = data.get('metadata', {})
                   click.echo(f"   Language: {metadata.get('language', 'unknown')}")
                   click.echo(f"   Complexity: {metadata.get('complexity_score', 0):.2f}")
       else:
           click.echo("❌ No results found")
   
   @cli.command()
   @click.argument('file_path', type=click.Path(exists=True))
   @click.option('--check-nam', is_flag=True, help='Check NAM compliance')
   @click.pass_context
   def analyze(ctx, file_path, check_nam):
       """Analyze a single file."""
       agent = ctx.obj['agent']
       validator = ctx.obj['validator']
       
       click.echo(f"🔍 Analyzing {file_path}...")
       
       with open(file_path, 'r') as f:
           content = f.read()
       
       # Register analysis tool
       def analyze_file(content):
           import ast
           try:
               tree = ast.parse(content)
               functions = len([n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)])
               classes = len([n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)])
               lines = len(content.splitlines())
               
               return {
                   "functions": functions,
                   "classes": classes,
                   "lines": lines,
                   "complexity": functions + classes * 2
               }
           except:
               return {"error": "Unable to parse file"}
       
       agent.register_tool("analyze_file", analyze_file)
       
       # Run analysis
       result = agent.execute_tool("analyze_file", {"content": content})
       
       if result["status"] == "success":
           analysis = result["result"]
           click.echo("📊 Analysis Results:")
           click.echo(f"  Functions: {analysis.get('functions', 0)}")
           click.echo(f"  Classes: {analysis.get('classes', 0)}")
           click.echo(f"  Lines: {analysis.get('lines', 0)}")
           click.echo(f"  Complexity: {analysis.get('complexity', 0)}")
           
           # NAM compliance check
           if check_nam:
               import numpy as np
               action_vector = np.array([analysis.get('complexity', 0)])
               nam_result = validator.validate_axiom("AX_NO_HARM")
               
               click.echo(f"🔒 NAM Compliance:")
               click.echo(f"  Valid: {nam_result['is_valid']}")
               click.echo(f"  Resonance: {nam_result['resonance_score']:.3f}")
               click.echo(f"  Tension: {nam_result['ethical_tension']:.3f}")
       else:
           click.echo(f"❌ Analysis failed: {result['error']}")
   
   @cli.command()
   @click.pass_context
   def status(ctx):
       """Show system status and statistics."""
       htm = ctx.obj['htm']
       agent = ctx.obj['agent']
       
       click.echo("📊 CBC System Status")
       
       # HTM storage stats
       htm_stats = htm.get_memory_stats()
       click.echo(f"🗄️  HTM Storage:")
       click.echo(f"   Used: {htm_stats.get('used', 0)} bytes")
       click.echo(f"   Total: {htm_stats.get('total', 0)} bytes")
       
       # Agent stats
       agent_stats = agent.get_memory_stats()
       click.echo(f"🤖 Agent Status:")
       click.echo(f"   Memory: {agent_stats.get('total_used', 0)} bytes")
       click.echo(f"   Tools: {len(agent.tools)}")
   
   if __name__ == '__main__':
       cli()

See Also
--------

* :doc:`../reference/cbc_core_api` - Rust Core API Reference
* :doc:`../reference/python_ffi_api` - Python FFI API Reference  
* :doc:`../reference/tensor_mem_ai_api` - TensorMem AI API Reference
* :doc:`../reference/grpc_api` - gRPC API Reference