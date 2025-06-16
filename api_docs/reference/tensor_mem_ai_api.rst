TensorMem AI Library API Reference
===================================

TensorMem AI is a high-level Python library that provides memory-aware AI agent capabilities with advanced tool chaining and multi-agent coordination built on top of the CBC Core.

.. contents:: Table of Contents
   :local:

Overview
--------

TensorMem AI provides:

* **TensorMemAgent** - High-performance AI agent with Rust-powered memory management
* **Tool System** - Advanced tool registry, chaining, and execution framework
* **Multi-Agent Coordination** - Sophisticated multi-agent orchestration capabilities
* **Memory Management** - Intelligent memory optimization and garbage collection
* **Async Support** - Full async/await compatibility for high-performance operations

Installation
------------

.. code-block:: bash

   # Install from PyPI
   pip install tensor-mem-ai
   
   # Install from source
   cd tensor_mem_ai
   pip install -e .

Quick Start
-----------

.. code-block:: python

   from tensor_mem_ai import TensorMemAgent, create_agent, create_tool_chain
   
   # Create agent with default configuration
   agent = create_agent("my_agent")
   
   # Register tools
   agent.register_tool("bash", lambda cmd: subprocess.run(cmd, shell=True, capture_output=True))
   agent.register_tool("analyze", lambda path: analyze_code(path))
   
   # Execute tools
   result = agent.execute_tool("bash", {"cmd": "ls -la"})
   print(f"Command output: {result['result']}")

TensorMemAgent Class
--------------------

The core agent class providing memory-aware AI capabilities.

Initialization
^^^^^^^^^^^^^^

.. code-block:: python

   from tensor_mem_ai import TensorMemAgent, AgentConfig, MemoryConfig
   
   class TensorMemAgent:
       def __init__(
           self,
           name: str = "default",
           config: Optional[AgentConfig] = None
       ) -> None:
           """Initialize TensorMemAgent."""

**AgentConfig:**

.. code-block:: python

   from dataclasses import dataclass
   from pathlib import Path
   
   @dataclass
   class MemoryConfig:
       initial_pool_size: int = 1024 * 1024 * 100  # 100MB
       max_pool_size: int = 1024 * 1024 * 1024     # 1GB
       gc_threshold: float = 0.8                    # Trigger GC at 80%
       enable_compression: bool = True
       cache_size: int = 1024 * 1024 * 50          # 50MB cache
   
   @dataclass
   class AgentConfig:
       memory_config: MemoryConfig = field(default_factory=MemoryConfig)
       max_concurrent_tools: int = 10
       tool_timeout: float = 30.0  # seconds
       enable_async: bool = True
       log_level: str = "INFO"
       workspace_path: Optional[Path] = None

**Example:**

.. code-block:: python

   from tensor_mem_ai import TensorMemAgent, AgentConfig, MemoryConfig
   from pathlib import Path
   
   # Custom memory configuration
   memory_config = MemoryConfig(
       initial_pool_size=1024 * 1024 * 200,  # 200MB
       max_pool_size=1024 * 1024 * 2048,     # 2GB
       gc_threshold=0.7,
       enable_compression=True,
       cache_size=1024 * 1024 * 100          # 100MB cache
   )
   
   # Agent configuration
   config = AgentConfig(
       memory_config=memory_config,
       max_concurrent_tools=15,
       tool_timeout=45.0,
       enable_async=True,
       log_level="DEBUG",
       workspace_path=Path("./workspace")
   )
   
   # Create agent
   agent = TensorMemAgent("advanced_agent", config)

Tool Management
^^^^^^^^^^^^^^^

.. code-block:: python

   class TensorMemAgent:
       def register_tool(
           self,
           name: str,
           tool: Callable,
           description: str = ""
       ) -> None:
           """Register a tool for the agent to use."""
           
       def execute_tool(
           self,
           tool_name: str,
           args: Dict[str, Any],
           context: Optional[Dict[str, Any]] = None
       ) -> Dict[str, Any]:
           """Execute a tool synchronously."""
           
       async def execute_tool_async(
           self,
           tool_name: str,
           args: Dict[str, Any],
           context: Optional[Dict[str, Any]] = None
       ) -> Dict[str, Any]:
           """Execute a tool asynchronously."""

**Example:**

.. code-block:: python

   import subprocess
   import json
   from tensor_mem_ai import TensorMemAgent
   
   agent = TensorMemAgent("tool_agent")
   
   # Register simple bash tool
   def bash_tool(command):
       result = subprocess.run(command, shell=True, capture_output=True, text=True)
       return {
           "stdout": result.stdout,
           "stderr": result.stderr,
           "returncode": result.returncode
       }
   
   agent.register_tool("bash", bash_tool, "Execute bash commands")
   
   # Register file analysis tool
   def analyze_file(file_path):
       with open(file_path, 'r') as f:
           content = f.read()
       return {
           "lines": len(content.splitlines()),
           "chars": len(content),
           "words": len(content.split())
       }
   
   agent.register_tool("analyze_file", analyze_file, "Analyze file statistics")
   
   # Execute tools
   bash_result = agent.execute_tool("bash", {"command": "ls -la"})
   print(f"Bash output: {bash_result['result']['stdout']}")
   
   file_result = agent.execute_tool("analyze_file", {"file_path": "README.md"})
   print(f"File stats: {file_result['result']}")

Tool Chaining
^^^^^^^^^^^^^

.. code-block:: python

   class TensorMemAgent:
       async def chain_tools_async(
           self,
           chain: List[Tuple[str, Dict[str, Any]]],
           context: Optional[Dict[str, Any]] = None
       ) -> List[Dict[str, Any]]:
           """Execute a chain of tools asynchronously."""

**Example:**

.. code-block:: python

   import asyncio
   from tensor_mem_ai import TensorMemAgent
   
   async def main():
       agent = TensorMemAgent("chain_agent")
       
       # Register tools
       agent.register_tool("create_file", lambda name, content: open(name, 'w').write(content))
       agent.register_tool("read_file", lambda name: open(name, 'r').read())
       agent.register_tool("count_lines", lambda content: len(content.splitlines()))
       
       # Define tool chain
       chain = [
           ("create_file", {"name": "test.txt", "content": "Line 1\nLine 2\nLine 3"}),
           ("read_file", {"name": "test.txt"}),
           ("count_lines", {"content": "_previous"})  # Use previous result
       ]
       
       # Execute chain
       results = await agent.chain_tools_async(chain)
       
       for i, result in enumerate(results):
           print(f"Step {i+1}: {result['status']} - {result['result']}")
   
   asyncio.run(main())

Memory Management
^^^^^^^^^^^^^^^^^

.. code-block:: python

   class TensorMemAgent:
       def get_memory_stats(self) -> Dict[str, Any]:
           """Get current memory statistics."""
           
       def optimize_memory(self, aggressive: bool = False) -> None:
           """Trigger memory optimization."""
           
       def cleanup(self) -> None:
           """Clean up agent resources."""

**Example:**

.. code-block:: python

   from tensor_mem_ai import TensorMemAgent
   
   agent = TensorMemAgent("memory_agent")
   
   # Monitor memory usage
   stats = agent.get_memory_stats()
   print(f"Rust memory: {stats['rust']['used']} bytes")
   print(f"Python memory: {stats['python']['rss']} bytes")
   print(f"Memory percentage: {stats['python']['percent']:.2f}%")
   
   # Optimize memory when needed
   if stats['python']['percent'] > 80:
       agent.optimize_memory(aggressive=True)
       print("Memory optimization completed")

Codebase Analysis
^^^^^^^^^^^^^^^^^

.. code-block:: python

   class TensorMemAgent:
       def analyze_codebase(self, path: Union[str, Path]) -> Dict[str, Any]:
           """Analyze a codebase using Rust-powered analysis."""

**Example:**

.. code-block:: python

   from tensor_mem_ai import TensorMemAgent
   from pathlib import Path
   
   agent = TensorMemAgent("analyzer")
   
   # Analyze project
   analysis = agent.analyze_codebase("./my_project")
   
   print(f"Files analyzed: {analysis.get('file_count', 0)}")
   print(f"Languages detected: {analysis.get('languages', [])}")
   print(f"Total lines: {analysis.get('total_lines', 0)}")
   print(f"Memory usage: {analysis.get('memory_usage', {})}")

Context Management
^^^^^^^^^^^^^^^^^^

.. code-block:: python

   # Use as context manager for automatic cleanup
   with TensorMemAgent("context_agent") as agent:
       agent.register_tool("test", lambda x: x * 2)
       result = agent.execute_tool("test", {"x": 21})
       print(f"Result: {result['result']}")
   # Agent automatically cleaned up

Tool System
-----------

Advanced tool management and execution framework.

ToolRegistry
^^^^^^^^^^^^

.. code-block:: python

   from tensor_mem_ai import ToolRegistry
   
   class ToolRegistry:
       def __init__(self) -> None:
           """Initialize tool registry."""
           
       def register(
           self,
           name: str,
           func: Callable,
           description: str = "",
           validator: Optional[Callable] = None,
           metadata: Optional[Dict[str, Any]] = None
       ) -> None:
           """Register a tool."""
           
       def get(self, name: str) -> Optional[Dict[str, Any]]:
           """Get tool by name."""
           
       def list_tools(self) -> List[str]:
           """List all registered tool names."""
           
       async def execute(self, name: str, args: Dict[str, Any]) -> ToolResult:
           """Execute a tool with middleware support."""

**Example:**

.. code-block:: python

   from tensor_mem_ai import ToolRegistry, ToolResult
   import asyncio
   
   # Create registry
   registry = ToolRegistry()
   
   # Register tools with validation
   def validate_math_args(args):
       return 'x' in args and isinstance(args['x'], (int, float))
   
   registry.register(
       "square",
       func=lambda x: x ** 2,
       description="Square a number",
       validator=validate_math_args,
       metadata={"category": "math", "complexity": "low"}
   )
   
   registry.register(
       "factorial",
       func=lambda n: 1 if n <= 1 else n * factorial(n-1),
       description="Calculate factorial",
       validator=lambda args: 'n' in args and isinstance(args['n'], int) and args['n'] >= 0
   )
   
   async def main():
       # Execute tools
       result = await registry.execute("square", {"x": 5})
       print(f"Square result: {result.output}")  # 25
       
       result = await registry.execute("factorial", {"n": 5})
       print(f"Factorial result: {result.output}")  # 120
       
       # List available tools
       tools = registry.list_tools()
       print(f"Available tools: {tools}")
   
   asyncio.run(main())

ToolResult Class
^^^^^^^^^^^^^^^^

.. code-block:: python

   from dataclasses import dataclass
   from typing import Any, Dict, Optional
   
   @dataclass
   class ToolResult:
       status: str  # success, error, timeout
       output: Any
       error: Optional[str] = None
       duration: float = 0.0
       metadata: Dict[str, Any] = None
       
       @property
       def success(self) -> bool:
           """Check if execution was successful."""
           return self.status == "success"

BashTool
^^^^^^^^

Advanced bash command execution with chaining support.

.. code-block:: python

   from tensor_mem_ai import BashTool
   from pathlib import Path
   
   class BashTool:
       def __init__(
           self,
           working_dir: Optional[Path] = None,
           timeout: float = 30.0
       ) -> None:
           """Initialize BashTool."""
           
       def execute(
           self,
           command: str,
           input_data: Optional[str] = None,
           env_vars: Optional[Dict[str, str]] = None,
           capture_output: bool = True
       ) -> ToolResult:
           """Execute a bash command."""
           
       async def execute_async(self, command: str, **kwargs) -> ToolResult:
           """Execute command asynchronously."""
           
       def chain(self, commands: List[str]) -> List[ToolResult]:
           """Execute a chain of commands."""
           
       async def chain_async(self, commands: List[str]) -> List[ToolResult]:
           """Execute command chain asynchronously."""

**Example:**

.. code-block:: python

   from tensor_mem_ai import BashTool
   from pathlib import Path
   
   # Create bash tool
   bash = BashTool(working_dir=Path("./project"), timeout=60.0)
   
   # Execute single command
   result = bash.execute("ls -la")
   if result.success:
       print(f"Directory listing:\n{result.output}")
   else:
       print(f"Command failed: {result.error}")
   
   # Execute with environment variables
   result = bash.execute(
       "echo $MY_VAR",
       env_vars={"MY_VAR": "Hello World"}
   )
   print(f"Environment variable: {result.output}")
   
   # Execute command chain
   commands = [
       "mkdir -p build",
       "cd build",
       "cmake ..",
       "make -j4"
   ]
   
   results = bash.chain(commands)
   for i, result in enumerate(results):
       print(f"Command {i+1}: {result.status}")
       if not result.success:
           print(f"Build failed at step {i+1}")
           break

FileSystemTool
^^^^^^^^^^^^^^

Advanced file system operations with sandboxing.

.. code-block:: python

   from tensor_mem_ai import FileSystemTool
   from pathlib import Path
   
   class FileSystemTool:
       def __init__(self, base_path: Optional[Path] = None) -> None:
           """Initialize with optional base path for sandboxing."""
           
       def read(self, path: Union[str, Path], encoding: str = "utf-8") -> ToolResult:
           """Read file contents."""
           
       def write(
           self,
           path: Union[str, Path],
           content: str,
           encoding: str = "utf-8",
           create_dirs: bool = True
       ) -> ToolResult:
           """Write content to file."""
           
       def list_files(
           self,
           path: Union[str, Path] = ".",
           pattern: str = "*",
           recursive: bool = False
       ) -> ToolResult:
           """List files in directory."""
           
       def delete(self, path: Union[str, Path], recursive: bool = False) -> ToolResult:
           """Delete file or directory."""

**Example:**

.. code-block:: python

   from tensor_mem_ai import FileSystemTool
   from pathlib import Path
   
   # Create file system tool with sandboxing
   fs = FileSystemTool(base_path=Path("./workspace"))
   
   # Write file
   result = fs.write("config/settings.json", '{"debug": true}')
   if result.success:
       print(f"File written: {result.output}")
   
   # Read file
   result = fs.read("config/settings.json")
   if result.success:
       print(f"File content: {result.output}")
   
   # List Python files recursively
   result = fs.list_files(".", pattern="*.py", recursive=True)
   if result.success:
       print(f"Python files: {result.output}")
   
   # Delete with safety check
   result = fs.delete("temp/cache", recursive=True)
   if result.success:
       print("Cache deleted successfully")

ToolChain
^^^^^^^^^

Sophisticated tool chaining for complex workflows.

.. code-block:: python

   from tensor_mem_ai import ToolChain
   
   class ToolChain:
       def __init__(self, tools: List[Tuple[Any, Dict[str, Any]]] = None) -> None:
           """Initialize ToolChain."""
           
       def add(self, tool: Any, args: Dict[str, Any] = None) -> "ToolChain":
           """Add tool to chain."""
           
       async def execute_async(self) -> List[ToolResult]:
           """Execute tool chain asynchronously."""
           
       def execute(self) -> List[ToolResult]:
           """Execute tool chain synchronously."""

**Example:**

.. code-block:: python

   from tensor_mem_ai import ToolChain, BashTool, FileSystemTool
   
   # Create tools
   bash = BashTool()
   fs = FileSystemTool()
   
   # Create chain
   chain = ToolChain()
   chain.add(bash, {"command": "git clone https://github.com/user/repo.git"})
   chain.add(fs, {"method": "list_files", "path": "repo", "pattern": "*.py", "recursive": True})
   chain.add(bash, {"command": "wc -l repo/**/*.py"})
   
   # Execute chain
   results = chain.execute()
   
   for i, result in enumerate(results):
       print(f"Step {i+1}: {result.status}")
       if result.success:
           print(f"  Output: {result.output}")
       else:
           print(f"  Error: {result.error}")

Multi-Agent Coordination
------------------------

Advanced multi-agent orchestration capabilities.

MultiAgentCoordinator
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from tensor_mem_ai import MultiAgentCoordinator
   
   class MultiAgentCoordinator:
       def __init__(self, max_agents: int = 5) -> None:
           """Initialize coordinator."""
           
       def register_agent(self, name: str, agent: Any) -> None:
           """Register an agent."""
           
       async def delegate_task(
           self,
           agent_name: str,
           task: str,
           args: Dict[str, Any],
           timeout: Optional[float] = None
       ) -> ToolResult:
           """Delegate task to specific agent."""
           
       async def broadcast_task(
           self,
           task: str,
           args: Dict[str, Any],
           timeout: Optional[float] = None
       ) -> Dict[str, ToolResult]:
           """Broadcast task to all agents."""
           
       async def consensus_task(
           self,
           task: str,
           args: Dict[str, Any],
           consensus_func: Callable[[List[Any]], Any],
           timeout: Optional[float] = None
       ) -> ToolResult:
           """Execute task with consensus from multiple agents."""

**Example:**

.. code-block:: python

   import asyncio
   from tensor_mem_ai import TensorMemAgent, MultiAgentCoordinator
   
   async def main():
       # Create agents
       analyzer_agent = TensorMemAgent("analyzer")
       validator_agent = TensorMemAgent("validator")
       optimizer_agent = TensorMemAgent("optimizer")
       
       # Register agent capabilities
       analyzer_agent.register_tool("analyze_code", lambda code: {"complexity": len(code.split())})
       validator_agent.register_tool("validate_syntax", lambda code: {"valid": "def " in code})
       optimizer_agent.register_tool("optimize_code", lambda code: {"optimized": code.replace("  ", " ")})
       
       # Create coordinator
       coordinator = MultiAgentCoordinator(max_agents=3)
       coordinator.register_agent("analyzer", analyzer_agent)
       coordinator.register_agent("validator", validator_agent)
       coordinator.register_agent("optimizer", optimizer_agent)
       
       # Delegate specific task
       code = "def hello():  return 'world'"
       result = await coordinator.delegate_task(
           "analyzer",
           "analyze_code",
           {"code": code}
       )
       print(f"Analysis result: {result.output}")
       
       # Broadcast task to all agents
       all_results = await coordinator.broadcast_task(
           "process_code",
           {"code": code},
           timeout=30.0
       )
       
       for agent_name, result in all_results.items():
           print(f"{agent_name}: {result.status} - {result.output}")
       
       # Consensus task
       def consensus_func(outputs):
           # Simple majority consensus
           return max(set(outputs), key=outputs.count)
       
       consensus_result = await coordinator.consensus_task(
           "validate_quality",
           {"code": code},
           consensus_func,
           timeout=45.0
       )
       print(f"Consensus result: {consensus_result.output}")
   
   asyncio.run(main())

Utility Functions
-----------------

Convenient factory functions and utilities.

Factory Functions
^^^^^^^^^^^^^^^^^

.. code-block:: python

   from tensor_mem_ai import create_agent, create_tool_chain
   
   def create_agent(name: str = "default", config: AgentConfig = None) -> TensorMemAgent:
       """Factory function to create a new TensorMemAgent instance."""
       
   def create_tool_chain(*tools) -> ToolChain:
       """Create a tool chain for sequential tool execution."""

**Example:**

.. code-block:: python

   from tensor_mem_ai import create_agent, create_tool_chain, BashTool, FileSystemTool
   
   # Quick agent creation
   agent = create_agent("quick_agent")
   
   # Quick tool chain creation
   bash = BashTool()
   fs = FileSystemTool()
   
   chain = create_tool_chain(
       (bash, {"command": "git status"}),
       (fs, {"method": "read", "path": "README.md"}),
       (bash, {"command": "echo 'Processing complete'"})
   )
   
   results = chain.execute()
   print(f"Chain completed with {len(results)} steps")

Performance Monitoring
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from tensor_mem_ai import TensorMemAgent
   
   # Enable performance monitoring
   agent = TensorMemAgent("perf_agent")
   
   # Get execution statistics
   stats = agent.get_memory_stats()
   print(f"Memory efficiency: {stats['rust']['used'] / stats['rust']['total'] * 100:.1f}%")
   
   # Benchmark tool execution
   import time
   
   start_time = time.time()
   result = agent.execute_tool("example_tool", {"data": "test"})
   execution_time = time.time() - start_time
   
   print(f"Tool executed in {execution_time:.3f} seconds")

Configuration
-------------

Global configuration for TensorMem AI.

.. code-block:: python

   from tensor_mem_ai import configure
   
   # Configure global settings
   configure({
       "default_memory_limit": 1024 * 1024 * 1024,  # 1GB
       "default_timeout": 60.0,
       "enable_profiling": True,
       "log_level": "INFO",
       "max_concurrent_agents": 10,
   })

Error Handling
--------------

Comprehensive error handling with custom exceptions.

.. code-block:: python

   from tensor_mem_ai.exceptions import (
       TensorMemError,
       ToolExecutionError,
       MemoryError,
       TimeoutError,
       ConfigurationError
   )
   
   try:
       agent = TensorMemAgent("test")
       result = agent.execute_tool("nonexistent_tool", {})
   except ToolExecutionError as e:
       print(f"Tool execution failed: {e}")
   except MemoryError as e:
       print(f"Memory limit exceeded: {e}")
   except TensorMemError as e:
       print(f"General TensorMem error: {e}")

Async Patterns
--------------

Best practices for async usage.

.. code-block:: python

   import asyncio
   from tensor_mem_ai import TensorMemAgent
   
   async def parallel_processing():
       agent = TensorMemAgent("async_agent")
       
       # Register async tools
       async def async_fetch(url):
           # Simulate API call
           await asyncio.sleep(1)
           return {"url": url, "status": "fetched"}
       
       agent.register_tool("fetch", async_fetch)
       
       # Execute multiple tools in parallel
       tasks = [
           agent.execute_tool_async("fetch", {"url": f"https://api.example.com/{i}"})
           for i in range(5)
       ]
       
       results = await asyncio.gather(*tasks)
       
       for i, result in enumerate(results):
           print(f"Task {i+1}: {result['status']}")
   
   # Run with asyncio
   asyncio.run(parallel_processing())

Integration Examples
--------------------

Real-world integration patterns.

Code Analysis Pipeline
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   import asyncio
   from tensor_mem_ai import TensorMemAgent, ToolChain, BashTool, FileSystemTool
   
   async def analyze_repository():
       # Create specialized agent
       analyzer = TensorMemAgent("code_analyzer")
       
       # Register analysis tools
       def extract_functions(code):
           import ast
           tree = ast.parse(code)
           functions = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
           return {"functions": functions, "count": len(functions)}
       
       def calculate_complexity(code):
           # Simple complexity metric
           complexity = len(code.split()) + code.count("if") * 2 + code.count("for") * 2
           return {"complexity": complexity, "level": "high" if complexity > 100 else "medium" if complexity > 50 else "low"}
       
       analyzer.register_tool("extract_functions", extract_functions)
       analyzer.register_tool("calculate_complexity", calculate_complexity)
       
       # Create analysis pipeline
       fs = FileSystemTool()
       chain = ToolChain()
       
       # Add steps to chain
       chain.add(fs, {"method": "list_files", "pattern": "*.py", "recursive": True})
       
       # Execute pipeline
       results = await chain.execute_async()
       
       # Process each Python file
       for file_path in results[0].output:
           file_content = fs.read(file_path).output
           
           # Extract functions
           functions = analyzer.execute_tool("extract_functions", {"code": file_content})
           
           # Calculate complexity
           complexity = analyzer.execute_tool("calculate_complexity", {"code": file_content})
           
           print(f"File: {file_path}")
           print(f"  Functions: {functions['result']['count']}")
           print(f"  Complexity: {complexity['result']['level']}")
   
   asyncio.run(analyze_repository())

See Also
--------

* :doc:`cbc_core_api` - Rust Core API
* :doc:`python_ffi_api` - Python FFI bindings
* :doc:`grpc_api` - gRPC service definitions
* :doc:`../examples/tensor_mem_ai_examples` - Usage examples