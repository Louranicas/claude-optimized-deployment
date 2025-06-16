# MCP Server Development Guidelines and Standards

This document outlines the coding standards, testing requirements, documentation standards, and review checklists for developing MCP servers following our standardized architecture.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Coding Standards](#coding-standards)
3. [Testing Requirements](#testing-requirements)
4. [Documentation Standards](#documentation-standards)
5. [Security Guidelines](#security-guidelines)
6. [Performance Best Practices](#performance-best-practices)
7. [Error Handling Patterns](#error-handling-patterns)
8. [Logging Standards](#logging-standards)
9. [Configuration Management](#configuration-management)
10. [Review Checklists](#review-checklists)
11. [Deployment Guidelines](#deployment-guidelines)

## Architecture Overview

All MCP servers must follow the standardized architecture pattern:

```
src/
├── core/               # Base classes and utilities
│   ├── base-server.ts  # Base server implementation
│   ├── interfaces.ts   # Common interface definitions
│   ├── utils.ts        # Shared utility functions
│   ├── logger.ts       # Logging infrastructure
│   └── config-manager.ts # Configuration management
├── communication/      # Protocol implementations
│   └── protocols.ts    # JSON-RPC, REST, WebSocket, gRPC
├── discovery/          # Service discovery
│   └── service-registry.ts # Service registration and discovery
├── tools/              # Tool implementations
├── resources/          # Resource implementations
└── health/             # Health monitoring
```

### Key Principles

1. **Consistency**: All servers follow the same architectural patterns
2. **Extensibility**: Easy to add new tools, resources, and protocols
3. **Observability**: Comprehensive logging, metrics, and health monitoring
4. **Reliability**: Error handling, circuit breakers, and graceful degradation
5. **Security**: Authentication, authorization, and input validation

## Coding Standards

### TypeScript Standards

#### File Organization
- Use kebab-case for file names: `tool-manager.ts`
- Use PascalCase for class names: `ToolManager`
- Use camelCase for function and variable names: `executeQuery`
- Use SCREAMING_SNAKE_CASE for constants: `MAX_RETRY_ATTEMPTS`

#### Code Style
```typescript
// ✅ Good
export class DatabaseTool extends BaseTool {
  private readonly config: DatabaseConfig;
  
  constructor(config: DatabaseConfig) {
    super();
    this.config = config;
  }
  
  public async execute(params: QueryParams): Promise<QueryResult> {
    const startTime = Date.now();
    
    try {
      // Implementation
      return result;
    } catch (error) {
      this.logger.logError(error, { params });
      throw error;
    } finally {
      const duration = Date.now() - startTime;
      this.logger.logPerformance('database_query', duration);
    }
  }
}

// ❌ Bad
class databaseTool {
  config: any;
  
  execute(params) {
    // No error handling or logging
    return this.db.query(params);
  }
}
```

#### Interface Definitions
```typescript
// ✅ Good - Comprehensive interface
export interface DatabaseToolConfig {
  connectionString: string;
  maxConnections: number;
  queryTimeout: number;
  retryAttempts: number;
  ssl?: SSLConfig;
}

export interface QueryParams {
  query: string;
  parameters?: Record<string, any>;
  timeout?: number;
}

export interface QueryResult {
  rows: any[];
  rowCount: number;
  executionTime: number;
  metadata?: QueryMetadata;
}
```

### Python Standards

#### File Organization
- Use snake_case for file names: `tool_manager.py`
- Use PascalCase for class names: `ToolManager`
- Use snake_case for function and variable names: `execute_query`
- Use SCREAMING_SNAKE_CASE for constants: `MAX_RETRY_ATTEMPTS`

#### Code Style
```python
# ✅ Good
@dataclass
class DatabaseConfig:
    connection_string: str
    max_connections: int = 10
    query_timeout: int = 30
    retry_attempts: int = 3

class DatabaseTool(BaseTool):
    def __init__(self, config: DatabaseConfig):
        super().__init__()
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    async def execute(self, params: QueryParams) -> QueryResult:
        start_time = time.time()
        
        try:
            # Implementation
            return result
        except Exception as error:
            self.logger.error(f"Query failed: {error}", extra={"params": params})
            raise
        finally:
            duration = (time.time() - start_time) * 1000
            self.logger.info(f"Query completed in {duration}ms")
```

### Rust Standards

#### File Organization
- Use snake_case for file names: `tool_manager.rs`
- Use PascalCase for struct names: `ToolManager`
- Use snake_case for function and variable names: `execute_query`
- Use SCREAMING_SNAKE_CASE for constants: `MAX_RETRY_ATTEMPTS`

#### Code Style
```rust
// ✅ Good
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub connection_string: String,
    pub max_connections: u32,
    pub query_timeout: Duration,
    pub retry_attempts: u32,
}

pub struct DatabaseTool {
    config: DatabaseConfig,
    logger: Logger,
}

impl DatabaseTool {
    pub fn new(config: DatabaseConfig) -> Self {
        Self {
            config,
            logger: tracing::logger(),
        }
    }
    
    pub async fn execute(&self, params: QueryParams) -> Result<QueryResult, DatabaseError> {
        let start_time = Instant::now();
        
        let result = match self.execute_query(&params).await {
            Ok(result) => result,
            Err(error) => {
                tracing::error!("Query failed: {}", error);
                return Err(error);
            }
        };
        
        let duration = start_time.elapsed();
        tracing::info!("Query completed in {:?}", duration);
        
        Ok(result)
    }
}
```

## Testing Requirements

### Unit Tests
Every public method must have unit tests with:
- Happy path scenarios
- Error conditions
- Edge cases
- Mock dependencies

#### TypeScript Testing Example
```typescript
describe('DatabaseTool', () => {
  let tool: DatabaseTool;
  let mockConfig: DatabaseConfig;

  beforeEach(() => {
    mockConfig = {
      connectionString: 'test://localhost',
      maxConnections: 5,
      queryTimeout: 1000,
      retryAttempts: 2,
    };
    tool = new DatabaseTool(mockConfig);
  });

  describe('execute', () => {
    it('should execute query successfully', async () => {
      const params = { query: 'SELECT 1', parameters: {} };
      const result = await tool.execute(params);
      
      expect(result.rowCount).toBeGreaterThan(0);
      expect(result.executionTime).toBeGreaterThan(0);
    });

    it('should handle query timeout', async () => {
      const params = { query: 'SELECT SLEEP(10)', timeout: 100 };
      
      await expect(tool.execute(params)).rejects.toThrow('Query timeout');
    });

    it('should retry on connection failure', async () => {
      // Mock connection failure then success
      const params = { query: 'SELECT 1' };
      
      const result = await tool.execute(params);
      expect(result).toBeDefined();
    });
  });
});
```

### Integration Tests
Test complete workflows including:
- Server startup and shutdown
- Tool execution pipelines
- Resource access patterns
- Health check endpoints
- Service discovery

### Performance Tests
- Load testing for concurrent requests
- Memory usage monitoring
- Response time benchmarks
- Resource cleanup verification

### Security Tests
- Input validation testing
- Authentication/authorization
- Rate limiting effectiveness
- SQL injection prevention

## Documentation Standards

### Code Documentation

#### TypeScript JSDoc
```typescript
/**
 * Executes a database query with automatic retry and error handling.
 * 
 * @param params - Query parameters including SQL and bindings
 * @param options - Execution options like timeout and retry behavior
 * @returns Promise resolving to query results with metadata
 * @throws DatabaseError when query fails after all retries
 * 
 * @example
 * ```typescript
 * const result = await tool.execute({
 *   query: 'SELECT * FROM users WHERE id = ?',
 *   parameters: { id: 123 }
 * });
 * console.log(`Found ${result.rowCount} users`);
 * ```
 */
public async execute(
  params: QueryParams, 
  options?: ExecutionOptions
): Promise<QueryResult> {
  // Implementation
}
```

#### Python Docstrings
```python
async def execute(self, params: QueryParams, options: Optional[ExecutionOptions] = None) -> QueryResult:
    """Execute a database query with automatic retry and error handling.
    
    Args:
        params: Query parameters including SQL and bindings
        options: Execution options like timeout and retry behavior
        
    Returns:
        QueryResult: Query results with metadata
        
    Raises:
        DatabaseError: When query fails after all retries
        
    Example:
        >>> result = await tool.execute({
        ...     'query': 'SELECT * FROM users WHERE id = ?',
        ...     'parameters': {'id': 123}
        ... })
        >>> print(f"Found {result.row_count} users")
    """
```

### API Documentation
- OpenAPI/Swagger specs for REST endpoints
- JSON-RPC method documentation
- WebSocket message schemas
- Example requests and responses

### Architecture Documentation
- High-level system diagrams
- Data flow documentation
- Deployment architecture
- Security model description

## Security Guidelines

### Input Validation
```typescript
// ✅ Good - Comprehensive validation
export const queryParamsSchema = {
  type: 'object',
  properties: {
    query: { type: 'string', minLength: 1, maxLength: 10000 },
    parameters: { type: 'object' },
    timeout: { type: 'number', minimum: 100, maximum: 300000 }
  },
  required: ['query'],
  additionalProperties: false
};

public async execute(params: unknown): Promise<QueryResult> {
  const validatedParams = validateObject(params, queryParamsSchema);
  if (!validatedParams.valid) {
    throw new MCPError('INVALID_PARAMS', validatedParams.errors.join(', '));
  }
  
  // Sanitize SQL to prevent injection
  const sanitizedQuery = this.sanitizeQuery(params.query);
  
  // Implementation
}
```

### Authentication & Authorization
```typescript
// Implement authentication middleware
export class AuthenticationMiddleware {
  public async authenticate(token: string): Promise<User | null> {
    try {
      const decoded = jwt.verify(token, this.config.jwtSecret);
      return await this.userService.findById(decoded.sub);
    } catch {
      return null;
    }
  }
  
  public authorize(user: User, resource: string, action: string): boolean {
    return this.rbac.check(user.roles, resource, action);
  }
}
```

### Rate Limiting
```typescript
// Apply rate limiting to all endpoints
const rateLimiter = new RateLimiter({
  windowMs: 60000, // 1 minute
  maxRequests: 100, // per IP
  keyGenerator: (req) => req.ip
});

server.use(rateLimiter.middleware());
```

## Performance Best Practices

### Connection Pooling
```typescript
// ✅ Good - Use connection pools
export class DatabaseConnection {
  private pool: Pool;
  
  constructor(config: DatabaseConfig) {
    this.pool = new Pool({
      connectionString: config.connectionString,
      max: config.maxConnections,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    });
  }
}
```

### Caching Strategy
```typescript
// Implement caching for expensive operations
export class CachedTool extends BaseTool {
  private cache = new LRUCache<string, any>({ max: 1000 });
  
  public async execute(params: QueryParams): Promise<QueryResult> {
    const cacheKey = this.generateCacheKey(params);
    
    // Check cache first
    const cached = this.cache.get(cacheKey);
    if (cached) {
      return cached;
    }
    
    // Execute and cache result
    const result = await this.executeQuery(params);
    this.cache.set(cacheKey, result);
    
    return result;
  }
}
```

### Circuit Breaker Pattern
```typescript
// Implement circuit breakers for external services
const circuitBreaker = new CircuitBreaker(
  this.executeQuery.bind(this),
  {
    timeout: 3000,
    errorThresholdPercentage: 50,
    resetTimeout: 30000
  }
);

const result = await circuitBreaker.fire(params);
```

## Error Handling Patterns

### Structured Error Types
```typescript
// Define specific error types
export class DatabaseError extends MCPError {
  constructor(message: string, public readonly sqlState?: string) {
    super('DATABASE_ERROR', message, { sqlState });
  }
}

export class ConnectionError extends DatabaseError {
  constructor(message: string) {
    super(message);
    this.retryable = true;
  }
}
```

### Error Recovery
```typescript
// Implement retry logic with exponential backoff
export async function withRetry<T>(
  operation: () => Promise<T>,
  options: RetryOptions
): Promise<T> {
  let lastError: Error;
  
  for (let attempt = 1; attempt <= options.maxAttempts; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error as Error;
      
      if (!isRetryableError(error) || attempt === options.maxAttempts) {
        throw error;
      }
      
      const delay = Math.min(
        options.baseDelay * Math.pow(2, attempt - 1),
        options.maxDelay
      );
      
      await sleep(delay);
    }
  }
  
  throw lastError!;
}
```

## Logging Standards

### Structured Logging
```typescript
// Use structured logging with context
this.logger.info('Processing user query', {
  userId: user.id,
  queryType: params.type,
  duration: elapsed,
  success: true,
  metadata: {
    cacheHit: fromCache,
    rowCount: result.length
  }
});
```

### Log Levels
- **ERROR**: System errors, failures, exceptions
- **WARN**: Degraded performance, recoverable errors
- **INFO**: Normal operations, significant events
- **DEBUG**: Detailed execution flow, diagnostic info

### Security Logging
```typescript
// Log security events
this.logger.logSecurityEvent('authentication_failure', {
  userId: attempt.userId,
  ip: request.ip,
  userAgent: request.headers['user-agent'],
  reason: 'invalid_credentials'
});
```

## Configuration Management

### Environment-based Configuration
```typescript
// Support multiple configuration sources
export class ConfigManager {
  public loadConfig(): ServerConfig {
    const config = {
      // Default values
      database: {
        connectionString: 'postgresql://localhost:5432/app',
        maxConnections: 10
      }
    };
    
    // Override with config file
    const fileConfig = this.loadConfigFile();
    merge(config, fileConfig);
    
    // Override with environment variables
    const envConfig = this.loadEnvironmentConfig();
    merge(config, envConfig);
    
    // Validate final configuration
    this.validateConfig(config);
    
    return config;
  }
}
```

### Secret Management
```typescript
// Never commit secrets to version control
const config = {
  database: {
    connectionString: process.env.DATABASE_URL, // From environment
    password: await this.secretManager.get('database-password') // From secret store
  },
  jwt: {
    secret: process.env.JWT_SECRET || await this.secretManager.get('jwt-secret')
  }
};
```

## Review Checklists

### Code Review Checklist

#### Functionality
- [ ] Code implements the requirements correctly
- [ ] Edge cases are handled appropriately
- [ ] Error conditions are properly managed
- [ ] Input validation is comprehensive
- [ ] Output format matches specification

#### Architecture
- [ ] Follows established patterns and conventions
- [ ] Proper separation of concerns
- [ ] Dependencies are minimized and well-defined
- [ ] Interface contracts are clear
- [ ] Extensibility is considered

#### Security
- [ ] Input sanitization is implemented
- [ ] Authentication/authorization is enforced
- [ ] Sensitive data is protected
- [ ] SQL injection prevention
- [ ] Rate limiting is applied

#### Performance
- [ ] Database queries are optimized
- [ ] Caching is used appropriately
- [ ] Memory usage is reasonable
- [ ] No obvious performance bottlenecks
- [ ] Resource cleanup is handled

#### Testing
- [ ] Unit tests cover happy path and error cases
- [ ] Integration tests verify end-to-end functionality
- [ ] Performance tests validate scalability
- [ ] Security tests check vulnerabilities
- [ ] Test coverage meets minimum requirements (80%)

#### Documentation
- [ ] Public APIs are documented
- [ ] Code comments explain complex logic
- [ ] README files are updated
- [ ] Configuration options are documented
- [ ] Examples are provided

### Deployment Review Checklist

#### Configuration
- [ ] All environment variables are documented
- [ ] Default values are sensible
- [ ] Configuration validation is implemented
- [ ] Secrets are properly managed
- [ ] Feature flags are configured

#### Monitoring
- [ ] Health check endpoints are implemented
- [ ] Metrics are collected and exported
- [ ] Logging is comprehensive and structured
- [ ] Error tracking is configured
- [ ] Performance monitoring is setup

#### Security
- [ ] Security headers are configured
- [ ] HTTPS is enforced
- [ ] Input validation is comprehensive
- [ ] Rate limiting is enabled
- [ ] Security scanning is performed

#### Scalability
- [ ] Horizontal scaling is supported
- [ ] Database connections are pooled
- [ ] Caching is implemented
- [ ] Circuit breakers are configured
- [ ] Load balancing is setup

## Deployment Guidelines

### Container Standards
```dockerfile
# Use specific version tags
FROM node:18.17-alpine

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

# Set working directory
WORKDIR /app

# Copy dependency files first for layer caching
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Copy application code
COPY --chown=nextjs:nodejs . .

# Switch to non-root user
USER nextjs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Start command
CMD ["npm", "start"]
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mcp-server
  template:
    metadata:
      labels:
        app: mcp-server
    spec:
      containers:
      - name: mcp-server
        image: mcp-server:latest
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: "production"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: database-secret
              key: url
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
```

### Monitoring Setup
```yaml
# Prometheus monitoring
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: mcp-server
spec:
  selector:
    matchLabels:
      app: mcp-server
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
```

This comprehensive guide ensures all MCP servers follow consistent patterns for development, testing, deployment, and maintenance.