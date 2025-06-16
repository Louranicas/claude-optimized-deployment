/**
 * Example Optimized MCP Server
 * Demonstrates all performance optimization features
 */

import { OptimizedMCPServer, OptimizedServerConfig } from '../core/optimized-base-server';
import { Tool, Resource } from '@modelcontextprotocol/sdk/types.js';
import { memoize, debounce, batchAsync } from '../core/performance-optimizer';

export class OptimizedExampleServer extends OptimizedMCPServer {
  
  // Memoized expensive computation
  private expensiveCalculation = memoize((input: number) => {
    // Simulate expensive computation
    let result = 0;
    for (let i = 0; i < input * 1000000; i++) {
      result += Math.sqrt(i);
    }
    return result;
  });

  // Debounced logging to prevent spam
  private debouncedLog = debounce((message: string) => {
    this.logger.info(message);
  }, 1000);

  // Batched data processing
  private batchProcessor = batchAsync(async (items: any[]) => {
    // Process items in batch
    return items.map(item => ({ ...item, processed: true, timestamp: Date.now() }));
  }, 50, 100);

  protected async setupTools(): Promise<void> {
    // High-performance tool with caching
    const performanceDemo: Tool = {
      name: 'performance-demo',
      description: 'Demonstrates various performance optimizations',
      inputSchema: {
        type: 'object',
        properties: {
          operation: {
            type: 'string',
            enum: ['cpu-intensive', 'io-intensive', 'cached-operation', 'batch-processing', 'database-query']
          },
          input: { type: 'number', default: 100 },
          useCache: { type: 'boolean', default: true }
        },
        required: ['operation']
      }
    };

    // Data processing tool with worker threads
    const dataProcessor: Tool = {
      name: 'data-processor',
      description: 'Process large datasets using worker threads',
      inputSchema: {
        type: 'object',
        properties: {
          data: { type: 'array', items: { type: 'object' } },
          algorithm: {
            type: 'string',
            enum: ['sort', 'filter', 'transform', 'aggregate']
          },
          options: { type: 'object' }
        },
        required: ['data', 'algorithm']
      }
    };

    // Database operations tool
    const databaseOps: Tool = {
      name: 'database-ops',
      description: 'Optimized database operations with connection pooling',
      inputSchema: {
        type: 'object',
        properties: {
          operation: {
            type: 'string',
            enum: ['select', 'insert', 'update', 'delete', 'transaction']
          },
          table: { type: 'string' },
          data: { type: 'object' },
          where: { type: 'object' }
        },
        required: ['operation', 'table']
      }
    };

    // Cache management tool
    const cacheManager: Tool = {
      name: 'cache-manager',
      description: 'Manage cache operations',
      inputSchema: {
        type: 'object',
        properties: {
          action: {
            type: 'string',
            enum: ['get', 'set', 'delete', 'clear', 'stats']
          },
          key: { type: 'string' },
          value: { type: 'any' },
          ttl: { type: 'number' }
        },
        required: ['action']
      }
    };

    // Performance metrics tool
    const metricsCollector: Tool = {
      name: 'metrics-collector',
      description: 'Collect and analyze performance metrics',
      inputSchema: {
        type: 'object',
        properties: {
          type: {
            type: 'string',
            enum: ['current', 'history', 'alerts', 'health']
          },
          duration: { type: 'number', default: 3600 }
        },
        required: ['type']
      }
    };

    this.registerTool(performanceDemo);
    this.registerTool(dataProcessor);
    this.registerTool(databaseOps);
    this.registerTool(cacheManager);
    this.registerTool(metricsCollector);
  }

  protected async setupResources(): Promise<void> {
    // Performance dashboard resource
    const dashboard: Resource = {
      uri: 'performance://dashboard',
      name: 'Performance Dashboard',
      description: 'Real-time performance metrics and optimization status',
      mimeType: 'application/json'
    };

    // System status resource
    const systemStatus: Resource = {
      uri: 'system://status',
      name: 'System Status',
      description: 'Current system status and health metrics',
      mimeType: 'application/json'
    };

    // Configuration resource
    const config: Resource = {
      uri: 'config://optimization',
      name: 'Optimization Configuration',
      description: 'Current optimization settings and recommendations',
      mimeType: 'application/json'
    };

    this.registerResource(dashboard);
    this.registerResource(systemStatus);
    this.registerResource(config);
  }

  protected async executeTool(name: string, args: unknown): Promise<unknown> {
    const params = args as any;

    switch (name) {
      case 'performance-demo':
        return this.handlePerformanceDemo(params);
      
      case 'data-processor':
        return this.handleDataProcessor(params);
      
      case 'database-ops':
        return this.handleDatabaseOps(params);
      
      case 'cache-manager':
        return this.handleCacheManager(params);
      
      case 'metrics-collector':
        return this.handleMetricsCollector(params);
      
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }

  private async handlePerformanceDemo(params: any): Promise<any> {
    const { operation, input = 100, useCache = true } = params;
    const cacheKey = `performance-demo:${operation}:${input}`;

    return this.handleOptimizedRequest(
      'performance-demo',
      async () => {
        switch (operation) {
          case 'cpu-intensive':
            return this.handleCPUIntensiveOperation(input);
          
          case 'io-intensive':
            return this.handleIOIntensiveOperation(input);
          
          case 'cached-operation':
            return this.handleCachedOperation(input);
          
          case 'batch-processing':
            return this.handleBatchProcessing(input);
          
          case 'database-query':
            return this.handleDatabaseQuery(input);
          
          default:
            throw new Error(`Unknown operation: ${operation}`);
        }
      },
      useCache ? cacheKey : undefined,
      3600 // 1 hour cache TTL
    );
  }

  private async handleCPUIntensiveOperation(input: number): Promise<any> {
    // Use memoization for repeated calculations
    const result = this.expensiveCalculation(input);
    
    // Log with debouncing to prevent spam
    this.debouncedLog(`CPU intensive operation completed: input=${input}, result=${result}`);
    
    return {
      operation: 'cpu-intensive',
      input,
      result,
      optimizations: ['memoization', 'debounced-logging'],
      executionTime: Date.now()
    };
  }

  private async handleIOIntensiveOperation(input: number): Promise<any> {
    // Simulate I/O operation with optimized HTTP client
    const agent = this.getOptimizedHttpAgent();
    
    // Simulate multiple I/O operations
    const promises = [];
    for (let i = 0; i < input; i++) {
      promises.push(this.simulateIOOperation(i));
    }
    
    const results = await Promise.all(promises);
    
    return {
      operation: 'io-intensive',
      input,
      results: results.length,
      optimizations: ['connection-pooling', 'parallel-processing'],
      executionTime: Date.now()
    };
  }

  private async handleCachedOperation(input: number): Promise<any> {
    const cacheKey = `cached-op:${input}`;
    
    // Try to get from cache first
    let result = await this.getCached<any>(cacheKey);
    
    if (!result) {
      // Perform expensive operation
      result = {
        computation: Math.pow(input, 3) * Math.PI,
        timestamp: Date.now(),
        cached: false
      };
      
      // Cache the result
      await this.setCached(cacheKey, result, 1800); // 30 minutes
    } else {
      result.cached = true;
    }
    
    return {
      operation: 'cached-operation',
      input,
      result,
      optimizations: ['lru-cache', 'redis-cache'],
      executionTime: Date.now()
    };
  }

  private async handleBatchProcessing(input: number): Promise<any> {
    // Generate test data
    const items = Array.from({ length: input }, (_, i) => ({
      id: i,
      value: Math.random() * 1000,
      category: `category-${i % 10}`
    }));
    
    // Process items using batch processor
    const processedItems = await Promise.all(
      items.map(item => this.batchProcessor(item))
    );
    
    return {
      operation: 'batch-processing',
      input,
      processedCount: processedItems.length,
      optimizations: ['batch-processing', 'async-queue'],
      executionTime: Date.now()
    };
  }

  private async handleDatabaseQuery(input: number): Promise<any> {
    try {
      // Simulate database operations with connection pooling
      const queries = [];
      
      for (let i = 0; i < input; i++) {
        queries.push(this.simulateDatabaseQuery(i));
      }
      
      const results = await Promise.all(queries);
      
      return {
        operation: 'database-query',
        input,
        results: results.length,
        optimizations: ['connection-pooling', 'prepared-statements'],
        executionTime: Date.now()
      };
    } catch (error) {
      return {
        operation: 'database-query',
        input,
        error: 'Database not configured',
        suggestion: 'Configure database connection pool for real database operations',
        executionTime: Date.now()
      };
    }
  }

  private async handleDataProcessor(params: any): Promise<any> {
    const { data, algorithm, options = {} } = params;
    
    if (!Array.isArray(data) || data.length === 0) {
      throw new Error('Data must be a non-empty array');
    }
    
    // Use worker threads for CPU-intensive data processing
    const result = await this.processCPUIntensiveTask({
      data,
      algorithm,
      options
    });
    
    return {
      algorithm,
      inputSize: data.length,
      result,
      optimizations: ['worker-threads', 'cpu-optimization'],
      executionTime: Date.now()
    };
  }

  private async handleDatabaseOps(params: any): Promise<any> {
    const { operation, table, data, where } = params;
    
    try {
      let result;
      
      switch (operation) {
        case 'select':
          result = await this.queryDatabase(
            `SELECT * FROM ${table} WHERE id = $1`,
            [where?.id || 1]
          );
          break;
          
        case 'insert':
          result = await this.queryDatabase(
            `INSERT INTO ${table} (data) VALUES ($1) RETURNING *`,
            [JSON.stringify(data)]
          );
          break;
          
        case 'update':
          result = await this.queryDatabase(
            `UPDATE ${table} SET data = $1 WHERE id = $2 RETURNING *`,
            [JSON.stringify(data), where?.id || 1]
          );
          break;
          
        case 'delete':
          result = await this.queryDatabase(
            `DELETE FROM ${table} WHERE id = $1`,
            [where?.id || 1]
          );
          break;
          
        case 'transaction':
          result = await this.transactionDatabase(async (client) => {
            // Simulate transaction operations
            const insert = await client.query(
              `INSERT INTO ${table} (data) VALUES ($1) RETURNING *`,
              [JSON.stringify(data)]
            );
            
            const update = await client.query(
              `UPDATE ${table} SET updated_at = NOW() WHERE id = $1`,
              [insert.rows[0].id]
            );
            
            return { insert: insert.rows, update: update.rowCount };
          });
          break;
          
        default:
          throw new Error(`Unknown database operation: ${operation}`);
      }
      
      return {
        operation,
        table,
        result,
        optimizations: ['connection-pooling', 'prepared-statements'],
        executionTime: Date.now()
      };
      
    } catch (error) {
      return {
        operation,
        table,
        error: 'Database operation failed - ensure database is configured',
        suggestion: 'Configure PostgreSQL or MySQL connection pool',
        executionTime: Date.now()
      };
    }
  }

  private async handleCacheManager(params: any): Promise<any> {
    const { action, key, value, ttl } = params;
    
    switch (action) {
      case 'get':
        if (!key) throw new Error('Key is required for get operation');
        const cachedValue = await this.getCached(key);
        return { action, key, value: cachedValue, found: cachedValue !== null };
      
      case 'set':
        if (!key || value === undefined) throw new Error('Key and value are required for set operation');
        await this.setCached(key, value, ttl);
        return { action, key, set: true };
      
      case 'delete':
        if (!key) throw new Error('Key is required for delete operation');
        await this.invalidateCache(key);
        return { action, key, deleted: true };
      
      case 'clear':
        await this.invalidateCachePattern('*');
        return { action, cleared: true };
      
      case 'stats':
        const metrics = this.getPerformanceMetrics();
        return {
          action,
          stats: {
            hitRate: metrics.cache?.hitRate || 0,
            missRate: metrics.cache?.missRate || 0,
            size: metrics.cache?.size || 0
          }
        };
      
      default:
        throw new Error(`Unknown cache action: ${action}`);
    }
  }

  private async handleMetricsCollector(params: any): Promise<any> {
    const { type, duration } = params;
    
    switch (type) {
      case 'current':
        return {
          type,
          metrics: this.getPerformanceMetrics(),
          connectionMetrics: this.getConnectionMetrics(),
          loadBalancerStats: this.getLoadBalancerStats(),
          timestamp: Date.now()
        };
      
      case 'history':
        const snapshot = this.getCurrentMonitoringSnapshot();
        return {
          type,
          snapshot,
          duration,
          timestamp: Date.now()
        };
      
      case 'alerts':
        // Get current alerts from performance monitor
        return {
          type,
          alerts: [], // This would come from the performance monitor
          timestamp: Date.now()
        };
      
      case 'health':
        const health = await this.getDetailedHealth();
        return {
          type,
          health,
          timestamp: Date.now()
        };
      
      default:
        throw new Error(`Unknown metrics type: ${type}`);
    }
  }

  protected async readResource(uri: string): Promise<any> {
    switch (uri) {
      case 'performance://dashboard':
        return this.getPerformanceDashboard();
      
      case 'system://status':
        return this.getSystemStatus();
      
      case 'config://optimization':
        return this.getOptimizationConfig();
      
      default:
        throw new Error(`Unknown resource: ${uri}`);
    }
  }

  private async getPerformanceDashboard(): Promise<any> {
    const metrics = this.getPerformanceMetrics();
    const connectionMetrics = this.getConnectionMetrics();
    const health = await this.getDetailedHealth();
    
    return {
      uri: 'performance://dashboard',
      mimeType: 'application/json',
      text: JSON.stringify({
        timestamp: Date.now(),
        performance: metrics,
        connections: connectionMetrics,
        health,
        optimizations: {
          caching: 'enabled',
          connectionPooling: 'enabled',
          workerThreads: 'enabled',
          loadBalancing: 'enabled',
          monitoring: 'enabled'
        }
      }, null, 2)
    };
  }

  private async getSystemStatus(): Promise<any> {
    const health = await this.getDetailedHealth();
    
    return {
      uri: 'system://status',
      mimeType: 'application/json',
      text: JSON.stringify({
        timestamp: Date.now(),
        status: health.status,
        uptime: Math.floor(process.uptime()),
        memory: process.memoryUsage(),
        cpu: process.cpuUsage(),
        version: process.version,
        platform: process.platform,
        arch: process.arch
      }, null, 2)
    };
  }

  private async getOptimizationConfig(): Promise<any> {
    return {
      uri: 'config://optimization',
      mimeType: 'application/json',
      text: JSON.stringify({
        timestamp: Date.now(),
        config: {
          performance: {
            workerThreads: 'enabled',
            threadPoolSize: 16,
            caching: 'redis+lru',
            connectionPooling: 'enabled'
          },
          monitoring: {
            dashboard: 'enabled',
            prometheus: 'enabled',
            alerts: 'enabled'
          },
          recommendations: [
            'Configure Redis for distributed caching',
            'Set up database connection pools',
            'Enable Prometheus monitoring',
            'Configure auto-scaling thresholds'
          ]
        }
      }, null, 2)
    };
  }

  // Helper methods
  private async simulateIOOperation(id: number): Promise<any> {
    // Simulate I/O delay
    await new Promise(resolve => setTimeout(resolve, Math.random() * 10));
    return { id, result: Math.random(), timestamp: Date.now() };
  }

  private async simulateDatabaseQuery(id: number): Promise<any> {
    // Simulate database query delay
    await new Promise(resolve => setTimeout(resolve, Math.random() * 5));
    return { id, data: `record-${id}`, timestamp: Date.now() };
  }
}

// Example usage and configuration
export const exampleServerConfig: OptimizedServerConfig = {
  name: 'optimized-example-server',
  version: '1.0.0',
  description: 'Example server demonstrating all performance optimizations',
  performance: {
    enableWorkerThreads: true,
    workerPoolSize: 8,
    threadPoolSize: 16,
    enableAsyncBatching: true,
    maxMemoryUsage: 28 * 1024, // 28GB
    gcThreshold: 75,
    enableMemoryProfiling: true,
    lruCacheSize: 10000,
    cacheTTL: 3600,
    enableRedisCache: true,
    redisUrl: 'redis://localhost:6379',
    dbConnectionPoolSize: 32,
    httpConnectionPoolSize: 64,
    keepAliveTimeout: 30000,
    enableMetrics: true,
    metricsInterval: 1000,
    alertThresholds: {
      cpuUsage: 85,
      memoryUsage: 90,
      responseTime: 5000
    }
  },
  connectionPool: {
    database: {
      postgres: {
        host: 'localhost',
        port: 5432,
        database: 'mcp_example',
        user: 'postgres',
        password: 'password',
        ssl: false,
        poolSize: 10,
        maxPoolSize: 32,
        idleTimeoutMillis: 300000,
        connectionTimeoutMillis: 10000
      }
    },
    http: {
      maxSockets: 64,
      maxFreeSockets: 16,
      timeout: 30000,
      keepAlive: true,
      keepAliveMsecs: 30000,
      freeSocketTimeout: 15000,
      socketActiveTTL: 300000
    }
  },
  monitoring: {
    dashboard: {
      enabled: true,
      port: 3001,
      host: '0.0.0.0',
      updateInterval: 1000
    },
    prometheus: {
      enabled: true,
      port: 9090,
      endpoint: '/metrics'
    },
    alerts: {
      enabled: true,
      thresholds: {
        cpuUsage: 80,
        memoryUsage: 85,
        responseTime: 5000,
        errorRate: 5,
        connectionPoolUtilization: 90
      }
    },
    retention: {
      metricsRetentionHours: 24,
      samplingInterval: 5000
    }
  },
  clustering: {
    enabled: true,
    workers: 16, // Match CPU cores
    gracefulShutdownTimeout: 30000
  }
};