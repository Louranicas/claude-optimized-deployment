# SYNTHEX-BashGod API Reference

## Core Types

### BashCommand
Individual bash command with metadata.

```rust
struct BashCommand {
    id: String,                    // Unique identifier
    command: String,               // Command name
    args: Vec<String>,            // Command arguments
    env: HashMap<String, String>, // Environment variables
    working_dir: Option<String>,  // Working directory
    resources: ResourceRequirements, // Resource limits
}
```

### CommandChain
Collection of commands with execution strategy.

```rust
struct CommandChain {
    id: String,                          // Chain identifier
    commands: Vec<BashCommand>,          // Commands to execute
    dependencies: HashMap<String, Vec<String>>, // Command dependencies
    strategy: ExecutionStrategy,         // How to execute
    metadata: ChainMetadata,            // Additional metadata
}
```

### ExecutionStrategy
How commands should be executed.

```rust
enum ExecutionStrategy {
    Sequential,                    // One by one
    Parallel { max_concurrent: usize }, // Concurrent execution
    Optimized,                    // Apply optimizations
    Predictive,                   // ML-based strategy
}
```

### ChainResult
Result of chain execution.

```rust
struct ChainResult {
    chain_id: String,                     // Chain ID
    command_results: Vec<CommandResult>,  // Individual results
    success: bool,                        // Overall success
    metrics: PerformanceMetrics,          // Performance data
    suggestions: Vec<OptimizationSuggestion>, // Improvements
}
```

## Service Trait

### BashGodService
Main service interface.

```rust
#[async_trait]
trait BashGodService {
    /// Execute a command chain
    async fn execute_chain(&self, chain: CommandChain) -> Result<ChainResult>;
    
    /// Optimize a command chain
    async fn optimize_chain(&self, chain: &CommandChain) -> Result<CommandChain>;
    
    /// Learn from execution results
    async fn learn_from_execution(&self, result: &ChainResult) -> Result<()>;
    
    /// Generate optimized chain from intent
    async fn generate_chain(&self, intent: BashIntent) -> Result<CommandChain>;
    
    /// Get learning insights
    async fn get_insights(&self) -> Result<Vec<LearningInsight>>;
}
```

## Python API

### PySynthexBashGod
Main Python class.

```python
class PySynthexBashGod:
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize SYNTHEX-BashGod.
        
        Args:
            config: Configuration dictionary with:
                - executor_pool_size: Number of concurrent executors
                - default_timeout_ms: Default command timeout
                - max_history_size: Learning history size
                - enable_caching: Enable result caching
                - enable_learning: Enable ML learning
                - enable_mcp_integration: Enable MCP tools
        """
    
    def execute_chain(self, chain: Dict) -> Dict:
        """
        Execute a command chain.
        
        Args:
            chain: Dictionary with:
                - id: Chain identifier
                - commands: List of command dictionaries
                - description: Chain description
                - resources: Resource requirements
                - strategy: Execution strategy (optional)
        
        Returns:
            Dictionary with:
                - chain_id: Chain identifier
                - success: Overall success flag
                - command_results: List of individual results
                - total_time_ms: Total execution time
                - metrics: Performance metrics
                - error: Error message if failed
        """
    
    def optimize_chain(self, chain: Dict) -> Dict:
        """
        Optimize a command chain.
        
        Args:
            chain: Command chain to optimize
        
        Returns:
            Optimized command chain with improved structure
        """
    
    def generate_chain(self, intent: Dict) -> Dict:
        """
        Generate command chain from natural language intent.
        
        Args:
            intent: Dictionary with:
                - goal: Natural language description
                - context: Additional context
                - constraints: List of constraints
                - examples: Example commands
        
        Returns:
            Generated command chain
        """
    
    def get_insights(self) -> List[Dict]:
        """
        Get learning insights.
        
        Returns:
            List of insight dictionaries with:
                - id: Insight identifier
                - insight_type: Type (pattern/optimization/etc)
                - description: Human-readable description
                - confidence: Confidence score (0-1)
                - occurrences: Number of occurrences
                - avg_improvement: Average improvement
                - examples: Example commands
                - recommendations: Suggested actions
        """
    
    def get_stats(self) -> Dict:
        """
        Get execution statistics.
        
        Returns:
            Dictionary with:
                - total_executions: Total chains executed
                - successful_executions: Successful completions
                - failed_executions: Failed executions
                - patterns_learned: Patterns identified
                - chains_optimized: Chains optimized
        """
```

## Configuration

### BashGodConfig
Service configuration.

```rust
struct BashGodConfig {
    // Executor settings
    executor_pool_size: usize,      // Default: 4
    default_timeout_ms: u64,        // Default: 30000
    max_history_size: usize,        // Default: 10000
    channel_buffer_size: usize,     // Default: 1000
    
    // Feature flags
    enable_caching: bool,           // Default: true
    enable_learning: bool,          // Default: true
    enable_mcp_integration: bool,   // Default: true
    
    // Memory configuration
    memory_config: MemoryConfig,
    
    // Learning configuration
    learning_config: LearningConfig,
    
    // MCP configuration
    mcp_config: MCPConfig,
}
```

### MemoryConfig
Memory system configuration.

```rust
struct MemoryConfig {
    tensor_size: usize,       // Vector storage capacity
    tensor_dim: usize,        // Vector dimensions
    graph_max_nodes: usize,   // Graph node limit
    gpu_enabled: bool,        // Enable GPU acceleration
    hybrid_weights: HybridWeights, // Memory type weights
}
```

### LearningConfig
Learning engine configuration.

```rust
struct LearningConfig {
    enable_continuous_learning: bool,  // Real-time learning
    lstm_hidden_size: usize,          // LSTM layer size
    pattern_threshold: f32,           // Pattern detection threshold
    optimization_threshold: f32,      // Optimization threshold
    prediction_confidence: f32,       // Prediction confidence
}
```

## Resource Management

### ResourceRequirements
Resource requirements for commands.

```rust
struct ResourceRequirements {
    cpu_cores: Option<f32>,      // CPU cores needed
    memory_mb: Option<u64>,      // Memory in MB
    disk_mb: Option<u64>,        // Disk space in MB
    network_mbps: Option<f32>,   // Network bandwidth
    gpu: bool,                   // GPU required
}
```

### ResourceLimits
Resource limits for execution.

```rust
struct ResourceLimits {
    max_cpu_percent: Option<f32>,
    max_memory_mb: Option<u64>,
    max_time_ms: Option<u64>,
    max_processes: Option<u32>,
    max_file_descriptors: Option<u32>,
}
```

## Learning Types

### LearningInsight
Insight from learning engine.

```rust
struct LearningInsight {
    id: String,
    insight_type: InsightType,
    description: String,
    confidence: f32,
    occurrences: u32,
    avg_improvement: f32,
    examples: Vec<String>,
    recommendations: String,
}
```

### InsightType
Types of learning insights.

```rust
enum InsightType {
    Pattern,        // Command pattern detected
    Optimization,   // Optimization opportunity
    AntiPattern,    // Problematic pattern
    Performance,    // Performance insight
    Resource,       // Resource usage insight
}
```

## MCP Integration

### MCPTool
MCP tool representation.

```rust
struct MCPTool {
    server: String,                           // Server name
    tool: String,                            // Tool name
    method: String,                          // Method to call
    params: HashMap<String, serde_json::Value>, // Parameters
    required_capabilities: Vec<String>,       // Required caps
}
```

### EnhancedCommand
Command enhanced with MCP.

```rust
struct EnhancedCommand {
    original: BashCommand,              // Original command
    enhancement: EnhancementType,       // Enhancement type
    mcp_tool: Option<MCPTool>,         // MCP tool to use
    strategy: ExecutionStrategy,        // Execution strategy
    performance_estimate: PerformanceEstimate, // Expected gains
}
```

## Error Types

### SBGError
SYNTHEX-BashGod errors.

```rust
enum SBGError {
    ExecutionError(String),      // Command execution failed
    OptimizationError(String),   // Optimization failed
    LearningError(String),       // Learning engine error
    MCPError(String),           // MCP integration error
    ResourceError(String),      // Resource limit exceeded
    ConfigError(String),        // Configuration error
    ActorError(String),         // Actor system error
    IOError(std::io::Error),    // I/O error
    NotImplemented(String),     // Feature not implemented
}
```

## Example Usage

### Basic Execution

```python
from rust_core import synthex_bashgod

# Initialize
sbg = synthex_bashgod.PySynthexBashGod()

# Create command chain
chain = {
    'id': 'example-1',
    'commands': [
        {
            'id': 'cmd-1',
            'command': 'echo',
            'args': ['Hello, World!'],
            'env': {},
            'working_dir': None,
            'resources': {}
        }
    ],
    'description': 'Simple echo test',
    'resources': {}
}

# Execute
result = sbg.execute_chain(chain)
print(f"Output: {result['command_results'][0]['stdout']}")
```

### Advanced Pipeline

```python
# Complex pipeline with optimization
chain = {
    'id': 'log-analysis',
    'commands': [
        {
            'id': 'find-logs',
            'command': 'find',
            'args': ['/var/log', '-name', '*.log', '-mtime', '-1'],
            'env': {},
            'working_dir': None,
            'resources': {'max_time_ms': 10000}
        },
        {
            'id': 'grep-errors',
            'command': 'xargs',
            'args': ['grep', '-H', 'ERROR'],
            'env': {},
            'working_dir': None,
            'resources': {}
        },
        {
            'id': 'sort-unique',
            'command': 'sort',
            'args': ['-u'],
            'env': {},
            'working_dir': None,
            'resources': {}
        },
        {
            'id': 'count',
            'command': 'wc',
            'args': ['-l'],
            'env': {},
            'working_dir': None,
            'resources': {}
        }
    ],
    'description': 'Find and count unique errors in recent logs',
    'resources': {
        'max_cpu_percent': 50,
        'max_memory_mb': 1024
    }
}

# Optimize before execution
optimized = sbg.optimize_chain(chain)
print(f"Optimized from {len(chain['commands'])} to {len(optimized['commands'])} commands")

# Execute optimized version
result = sbg.execute_chain(optimized)
```

### Intent-Based Generation

```python
# Generate chain from natural language
intent = {
    'goal': 'Monitor system resource usage and alert if CPU exceeds 80%',
    'context': {
        'monitoring_interval': '5s',
        'alert_method': 'email',
        'duration': '1h'
    },
    'constraints': ['efficient', 'reliable', 'low-overhead'],
    'examples': ['top', 'htop', 'sar']
}

chain = sbg.generate_chain(intent)
print(f"Generated {len(chain['commands'])} commands")
```

### Learning and Insights

```python
# Execute multiple chains to build learning data
for i in range(100):
    chain = create_test_chain(i)
    result = sbg.execute_chain(chain)
    
    # Learn from results
    if result['success']:
        print(f"Chain {i} succeeded in {result['total_time_ms']}ms")

# Get insights
insights = sbg.get_insights()
for insight in insights:
    if insight['confidence'] > 0.8:
        print(f"\n{insight['insight_type'].upper()}: {insight['description']}")
        print(f"Confidence: {insight['confidence']:.2f}")
        print(f"Occurrences: {insight['occurrences']}")
        print(f"Avg improvement: {insight['avg_improvement']:.2%}")
        print(f"Recommendation: {insight['recommendations']}")
```

## Performance Considerations

### Concurrency
- Default executor pool size: 4
- Maximum recommended: Number of CPU cores
- Each executor handles one command at a time

### Memory Usage
- Tensor memory: ~100MB per 10,000 patterns
- Graph memory: ~50MB per 10,000 nodes
- Command history: ~1KB per execution

### GPU Requirements
- Optional but recommended for large-scale learning
- Requires CUDA-capable GPU
- Falls back to CPU if unavailable

### Network Usage
- MCP servers: ~1KB per request
- Monitoring: ~10KB/s when active
- Updates: Periodic, configurable