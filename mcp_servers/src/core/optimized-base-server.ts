/**
 * Optimized Base MCP Server
 * High-performance implementation with all optimization features enabled
 */

import { BaseMCPServer, MCPServerOptions } from './base-server';
import { PerformanceOptimizer, PerformanceConfig } from './performance-optimizer';
import { ConnectionPoolManager, ConnectionPoolConfig } from './connection-pool';
import { LoadBalancer, createLoadBalancer } from './load-balancer';
import { PerformanceMonitor, createPerformanceMonitor, MonitoringConfig } from './performance-monitor';
import { createServerLogger } from './logger';
import { Logger } from 'pino';
import cluster from 'cluster';
import os from 'os';

export interface OptimizedServerConfig extends MCPServerOptions {
  performance?: Partial<PerformanceConfig>;
  connectionPool?: Partial<ConnectionPoolConfig>;
  monitoring?: Partial<MonitoringConfig>;
  clustering?: {
    enabled: boolean;
    workers?: number;
    gracefulShutdownTimeout?: number;
  };
}

export abstract class OptimizedMCPServer extends BaseMCPServer {
  private performanceOptimizer: PerformanceOptimizer;
  private connectionPool?: ConnectionPoolManager;
  private loadBalancer?: LoadBalancer;
  private performanceMonitor: PerformanceMonitor;
  private clusterId: string;

  constructor(config: OptimizedServerConfig) {
    super(config);
    
    this.clusterId = cluster.worker?.id?.toString() || 'master';
    this.logger = createServerLogger(`${config.name}-${this.clusterId}`);
    
    // Initialize performance optimizer
    this.performanceOptimizer = new PerformanceOptimizer(config.performance, this.logger);
    
    // Initialize connection pool if database config provided
    if (config.connectionPool) {
      this.connectionPool = new ConnectionPoolManager(
        config.connectionPool as ConnectionPoolConfig,
        this.logger
      );
    }

    // Initialize performance monitor
    this.performanceMonitor = createPerformanceMonitor(config.monitoring, this.logger);
    
    // Initialize load balancer for multi-instance deployments
    if (cluster.isWorker) {
      this.loadBalancer = createLoadBalancer('resource-based', {}, this.logger);
    }

    this.setupOptimizations();
    this.setupMonitoring();
  }

  private setupOptimizations(): void {
    // Set up performance optimizer event handlers
    this.performanceOptimizer.on('alert', (alert) => {
      this.logger.warn({ alert }, 'Performance alert triggered');
      this.emit('performance-alert', alert);
    });

    this.performanceOptimizer.on('metrics', (metrics) => {
      // Record metrics in performance monitor
      this.performanceMonitor.recordMetrics(
        this.clusterId,
        metrics,
        this.connectionPool ? this.connectionPool.getAllMetrics() : {}
      );
    });

    // Connection pool event handlers
    if (this.connectionPool) {
      this.connectionPool.on('error', (error) => {
        this.logger.error({ error }, 'Connection pool error');
        this.performanceOptimizer.trackError();
      });

      this.connectionPool.on('db-metrics', (metrics) => {
        this.logger.debug({ metrics }, 'Database metrics updated');
      });
    }

    // Load balancer event handlers
    if (this.loadBalancer) {
      this.loadBalancer.on('server-failed', (server) => {
        this.logger.warn({ serverId: server.id }, 'Load balancer detected server failure');
      });

      this.loadBalancer.on('scale-up-needed', (data) => {
        this.logger.info({ data }, 'Auto-scaling: scale up needed');
        this.emit('scale-up-needed', data);
      });

      this.loadBalancer.on('scale-down-needed', (data) => {
        this.logger.info({ data }, 'Auto-scaling: scale down possible');
        this.emit('scale-down-needed', data);
      });
    }
  }

  private setupMonitoring(): void {
    // Set up performance monitor event handlers
    this.performanceMonitor.on('alert', (alert) => {
      this.logger.warn({ alert }, 'Monitoring alert triggered');
      this.emit('monitoring-alert', alert);
    });

    this.performanceMonitor.on('metrics-recorded', (snapshot) => {
      this.logger.debug('Performance metrics recorded');
    });
  }

  // Enhanced request handling with performance optimizations
  protected async handleOptimizedRequest<T>(
    requestName: string,
    handler: () => Promise<T>,
    cacheKey?: string,
    cacheTTL?: number
  ): Promise<T> {
    const startTime = Date.now();
    this.performanceOptimizer.trackRequest();

    try {
      // Try cache first if cache key provided
      if (cacheKey) {
        const cachedResult = await this.performanceOptimizer.get<T>(cacheKey);
        if (cachedResult !== null) {
          this.performanceOptimizer.trackResponseTime(Date.now() - startTime);
          return cachedResult;
        }
      }

      // Process request asynchronously
      const result = await this.performanceOptimizer.processAsync(handler);

      // Cache result if cache key provided
      if (cacheKey) {
        await this.performanceOptimizer.set(cacheKey, result, cacheTTL);
      }

      this.performanceOptimizer.trackResponseTime(Date.now() - startTime);
      this.logger.info({ requestName, duration: Date.now() - startTime }, 'Request processed');

      return result;
    } catch (error) {
      this.performanceOptimizer.trackError();
      this.performanceOptimizer.trackResponseTime(Date.now() - startTime);
      this.logger.error({ error, requestName, duration: Date.now() - startTime }, 'Request failed');
      throw error;
    }
  }

  // CPU-intensive task processing with worker threads
  protected async processCPUIntensiveTask<T>(data: any): Promise<T> {
    return this.performanceOptimizer.processWithWorker<T>(data);
  }

  // Database operations with connection pooling
  protected async queryDatabase<T>(
    sql: string,
    params?: any[],
    dbType: 'postgres' | 'mysql' = 'postgres'
  ): Promise<T> {
    if (!this.connectionPool) {
      throw new Error('Connection pool not configured');
    }

    if (dbType === 'postgres') {
      return this.connectionPool.queryPostgres<T>(sql, params);
    } else {
      return this.connectionPool.queryMySQL<T>(sql, params);
    }
  }

  protected async transactionDatabase<T>(
    callback: (client: any) => Promise<T>,
    dbType: 'postgres' | 'mysql' = 'postgres'
  ): Promise<T> {
    if (!this.connectionPool) {
      throw new Error('Connection pool not configured');
    }

    if (dbType === 'postgres') {
      return this.connectionPool.transactionPostgres(callback);
    } else {
      return this.connectionPool.transactionMySQL(callback);
    }
  }

  // HTTP requests with connection pooling
  protected getOptimizedHttpAgent(): import('http').Agent {
    if (!this.connectionPool) {
      throw new Error('Connection pool not configured');
    }
    return this.connectionPool.getHttpAgent();
  }

  protected getOptimizedHttpsAgent(): import('https').Agent {
    if (!this.connectionPool) {
      throw new Error('Connection pool not configured');
    }
    return this.connectionPool.getHttpsAgent();
  }

  // Cache operations
  protected async getCached<T>(key: string): Promise<T | null> {
    return this.performanceOptimizer.get<T>(key);
  }

  protected async setCached<T>(key: string, value: T, ttl?: number): Promise<void> {
    return this.performanceOptimizer.set(key, value, ttl);
  }

  protected async invalidateCache(key: string): Promise<void> {
    return this.performanceOptimizer.invalidate(key);
  }

  protected async invalidateCachePattern(pattern: string): Promise<void> {
    return this.performanceOptimizer.invalidatePattern(pattern);
  }

  // Performance metrics
  getPerformanceMetrics() {
    return this.performanceOptimizer.getMetrics();
  }

  getConnectionMetrics() {
    return this.connectionPool ? this.connectionPool.getAllMetrics() : {};
  }

  getLoadBalancerStats() {
    return this.loadBalancer ? this.loadBalancer.getStatistics() : null;
  }

  getCurrentMonitoringSnapshot() {
    return this.performanceMonitor.getCurrentMetrics();
  }

  // Health checks
  async getDetailedHealth() {
    const baseHealth = await this.getHealth();
    
    return {
      ...baseHealth,
      performance: this.performanceOptimizer.getMetrics(),
      connectionPools: this.connectionPool ? await this.connectionPool.healthCheck() : {},
      loadBalancer: this.loadBalancer ? this.loadBalancer.getStatistics() : null,
      monitoring: {
        activeAlerts: this.performanceMonitor.getActiveAlertCount(),
        uptime: Math.floor(process.uptime())
      }
    };
  }

  // Enhanced cleanup
  protected async cleanup(): Promise<void> {
    this.logger.info('Starting optimized server cleanup');

    const cleanupPromises: Promise<void>[] = [];

    // Cleanup performance optimizer
    cleanupPromises.push(this.performanceOptimizer.cleanup());

    // Cleanup connection pool
    if (this.connectionPool) {
      cleanupPromises.push(this.connectionPool.close());
    }

    // Cleanup load balancer
    if (this.loadBalancer) {
      this.loadBalancer.destroy();
    }

    // Cleanup performance monitor
    cleanupPromises.push(this.performanceMonitor.cleanup());

    await Promise.all(cleanupPromises);

    this.logger.info('Optimized server cleanup completed');
  }
}

// Factory function for creating optimized servers
export function createOptimizedServer<T extends OptimizedMCPServer>(
  ServerClass: new (config: OptimizedServerConfig) => T,
  config: OptimizedServerConfig
): T {
  // Apply default optimizations for AMD Ryzen 7 7800X3D
  const optimizedConfig: OptimizedServerConfig = {
    ...config,
    performance: {
      enableWorkerThreads: true,
      workerPoolSize: Math.min(8, os.cpus().length - 2),
      threadPoolSize: os.cpus().length,
      enableAsyncBatching: true,
      maxMemoryUsage: 28 * 1024, // 28GB for 32GB system
      gcThreshold: 75,
      enableMemoryProfiling: true,
      lruCacheSize: 10000,
      cacheTTL: 3600,
      enableRedisCache: true,
      dbConnectionPoolSize: 32,
      httpConnectionPoolSize: 64,
      keepAliveTimeout: 30000,
      enableMetrics: true,
      metricsInterval: 1000,
      alertThresholds: {
        cpuUsage: 85,
        memoryUsage: 90,
        responseTime: 5000
      },
      ...config.performance
    },
    connectionPool: {
      http: {
        maxSockets: 64,
        maxFreeSockets: 16,
        timeout: 30000,
        keepAlive: true,
        keepAliveMsecs: 30000,
        freeSocketTimeout: 15000,
        socketActiveTTL: 300000
      },
      ...config.connectionPool
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
      },
      ...config.monitoring
    },
    clustering: {
      enabled: true,
      workers: os.cpus().length,
      gracefulShutdownTimeout: 30000,
      ...config.clustering
    }
  };

  return new ServerClass(optimizedConfig);
}

// Cluster management for multi-process deployment
export function startClusteredServer<T extends OptimizedMCPServer>(
  ServerClass: new (config: OptimizedServerConfig) => T,
  config: OptimizedServerConfig
): void {
  const numWorkers = config.clustering?.workers || os.cpus().length;

  if (cluster.isPrimary) {
    console.log(`Starting ${numWorkers} workers for ${config.name}`);

    // Fork workers
    for (let i = 0; i < numWorkers; i++) {
      cluster.fork();
    }

    cluster.on('exit', (worker, code, signal) => {
      console.log(`Worker ${worker.process.pid} died. Restarting...`);
      cluster.fork();
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      console.log('Primary received SIGTERM, shutting down workers...');
      
      Object.values(cluster.workers || {}).forEach(worker => {
        if (worker) {
          worker.kill('SIGTERM');
        }
      });

      setTimeout(() => {
        process.exit(0);
      }, config.clustering?.gracefulShutdownTimeout || 30000);
    });

  } else {
    // Worker process
    const server = createOptimizedServer(ServerClass, config);
    
    server.start().catch(error => {
      console.error('Failed to start worker server:', error);
      process.exit(1);
    });

    // Graceful shutdown for worker
    process.on('SIGTERM', async () => {
      console.log(`Worker ${process.pid} received SIGTERM, shutting down gracefully...`);
      await server.gracefulShutdown();
    });
  }
}