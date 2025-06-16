/**
 * Performance Optimizer for MCP Servers
 * Optimized for AMD Ryzen 7 7800X3D (16 threads) with 32GB RAM
 */

import os from 'os';
import { Worker } from 'worker_threads';
import { LRUCache } from 'lru-cache';
import { Redis } from 'ioredis';
import { EventEmitter } from 'events';
import { Logger } from 'pino';

// CPU Configuration for AMD Ryzen 7 7800X3D
const CPU_CORES = 16;
const THREAD_POOL_SIZE = CPU_CORES;
const WORKER_POOL_SIZE = Math.min(8, CPU_CORES - 2); // Reserve 2 cores for main process

export interface PerformanceConfig {
  // CPU Optimization
  enableWorkerThreads: boolean;
  workerPoolSize: number;
  threadPoolSize: number;
  enableAsyncBatching: boolean;
  
  // Memory Configuration (32GB RAM optimization)
  maxMemoryUsage: number; // in MB
  gcThreshold: number; // percentage
  enableMemoryProfiling: boolean;
  
  // Cache Configuration
  lruCacheSize: number;
  cacheTTL: number; // in seconds
  enableRedisCache: boolean;
  redisUrl?: string;
  
  // Connection Pooling
  dbConnectionPoolSize: number;
  httpConnectionPoolSize: number;
  keepAliveTimeout: number;
  
  // Performance Monitoring
  enableMetrics: boolean;
  metricsInterval: number;
  alertThresholds: {
    cpuUsage: number;
    memoryUsage: number;
    responseTime: number;
  };
}

export const defaultPerformanceConfig: PerformanceConfig = {
  // CPU Optimization for 16-thread Ryzen 7800X3D
  enableWorkerThreads: true,
  workerPoolSize: WORKER_POOL_SIZE,
  threadPoolSize: THREAD_POOL_SIZE,
  enableAsyncBatching: true,
  
  // Memory optimization for 32GB RAM
  maxMemoryUsage: 28 * 1024, // 28GB, leaving 4GB for system
  gcThreshold: 75,
  enableMemoryProfiling: true,
  
  // Cache configuration
  lruCacheSize: 10000,
  cacheTTL: 3600, // 1 hour
  enableRedisCache: true,
  redisUrl: 'redis://localhost:6379',
  
  // Connection pooling
  dbConnectionPoolSize: 32, // 2x CPU cores
  httpConnectionPoolSize: 64, // 4x CPU cores
  keepAliveTimeout: 30000,
  
  // Performance monitoring
  enableMetrics: true,
  metricsInterval: 1000,
  alertThresholds: {
    cpuUsage: 85,
    memoryUsage: 90,
    responseTime: 5000
  }
};

export interface PerformanceMetrics {
  timestamp: Date;
  cpu: {
    usage: number;
    loadAverage: number[];
    cores: number;
  };
  memory: {
    used: number;
    total: number;
    percentage: number;
    heapUsed: number;
    heapTotal: number;
  };
  cache: {
    hitRate: number;
    missRate: number;
    size: number;
  };
  requests: {
    total: number;
    persecond: number;
    averageResponseTime: number;
    errorRate: number;
  };
  connections: {
    active: number;
    waiting: number;
    pool: {
      db: number;
      http: number;
    };
  };
}

export class AsyncQueue {
  private queue: Array<() => Promise<any>> = [];
  private processing = false;
  private maxConcurrency: number;
  private currentConcurrency = 0;

  constructor(maxConcurrency: number = CPU_CORES) {
    this.maxConcurrency = maxConcurrency;
  }

  async add<T>(task: () => Promise<T>): Promise<T> {
    return new Promise((resolve, reject) => {
      this.queue.push(async () => {
        try {
          const result = await task();
          resolve(result);
        } catch (error) {
          reject(error);
        }
      });
      
      this.process();
    });
  }

  private async process(): Promise<void> {
    if (this.processing || this.currentConcurrency >= this.maxConcurrency) {
      return;
    }

    this.processing = true;

    while (this.queue.length > 0 && this.currentConcurrency < this.maxConcurrency) {
      const task = this.queue.shift();
      if (task) {
        this.currentConcurrency++;
        task().finally(() => {
          this.currentConcurrency--;
          this.process();
        });
      }
    }

    this.processing = false;
  }
}

export class WorkerThreadPool {
  private workers: Worker[] = [];
  private availableWorkers: Worker[] = [];
  private taskQueue: Array<{
    data: any;
    resolve: (value: any) => void;
    reject: (error: any) => void;
  }> = [];

  constructor(
    private poolSize: number,
    private workerScript: string
  ) {
    this.initializeWorkers();
  }

  private initializeWorkers(): void {
    for (let i = 0; i < this.poolSize; i++) {
      const worker = new Worker(this.workerScript, {
        resourceLimits: {
          maxOldGenerationSizeMb: 2048, // 2GB per worker
          maxYoungGenerationSizeMb: 512  // 512MB per worker
        }
      });

      worker.on('message', (result) => {
        this.availableWorkers.push(worker);
        this.processQueue();
      });

      worker.on('error', (error) => {
        console.error('Worker error:', error);
        // Replace failed worker
        this.replaceWorker(worker);
      });

      this.workers.push(worker);
      this.availableWorkers.push(worker);
    }
  }

  private replaceWorker(failedWorker: Worker): void {
    const index = this.workers.indexOf(failedWorker);
    if (index !== -1) {
      failedWorker.terminate();
      this.workers.splice(index, 1);
      
      const newWorker = new Worker(this.workerScript);
      this.workers.push(newWorker);
      this.availableWorkers.push(newWorker);
    }
  }

  async execute<T>(data: any): Promise<T> {
    return new Promise((resolve, reject) => {
      this.taskQueue.push({ data, resolve, reject });
      this.processQueue();
    });
  }

  private processQueue(): void {
    while (this.taskQueue.length > 0 && this.availableWorkers.length > 0) {
      const task = this.taskQueue.shift()!;
      const worker = this.availableWorkers.shift()!;

      const timeout = setTimeout(() => {
        task.reject(new Error('Worker task timeout'));
      }, 30000);

      const messageHandler = (result: any) => {
        clearTimeout(timeout);
        worker.off('message', messageHandler);
        worker.off('error', errorHandler);
        
        if (result.error) {
          task.reject(new Error(result.error));
        } else {
          task.resolve(result.data);
        }
        
        this.availableWorkers.push(worker);
        this.processQueue();
      };

      const errorHandler = (error: Error) => {
        clearTimeout(timeout);
        worker.off('message', messageHandler);
        worker.off('error', errorHandler);
        task.reject(error);
        this.replaceWorker(worker);
      };

      worker.on('message', messageHandler);
      worker.on('error', errorHandler);
      worker.postMessage(task.data);
    }
  }

  terminate(): void {
    this.workers.forEach(worker => worker.terminate());
    this.workers = [];
    this.availableWorkers = [];
  }
}

export class PerformanceOptimizer extends EventEmitter {
  private config: PerformanceConfig;
  private logger: Logger;
  private lruCache: LRUCache<string, any>;
  private redisCache?: Redis;
  private workerPool?: WorkerThreadPool;
  private asyncQueue: AsyncQueue;
  private metrics: PerformanceMetrics;
  private metricsInterval?: NodeJS.Timeout;
  
  // Request tracking
  private requestCount = 0;
  private errorCount = 0;
  private responseTimeSum = 0;
  private responseTimeCount = 0;
  
  // Cache tracking
  private cacheHits = 0;
  private cacheMisses = 0;

  constructor(config: Partial<PerformanceConfig> = {}, logger: Logger) {
    super();
    this.config = { ...defaultPerformanceConfig, ...config };
    this.logger = logger;
    this.asyncQueue = new AsyncQueue(this.config.threadPoolSize);
    
    this.initializeCache();
    this.initializeWorkerPool();
    this.initializeMonitoring();
    this.optimizeNodeJS();
  }

  private initializeCache(): void {
    // Initialize LRU Cache
    this.lruCache = new LRUCache({
      max: this.config.lruCacheSize,
      ttl: this.config.cacheTTL * 1000,
      allowStale: true,
      updateAgeOnGet: true,
      updateAgeOnHas: true
    });

    // Initialize Redis Cache if enabled
    if (this.config.enableRedisCache && this.config.redisUrl) {
      this.redisCache = new Redis(this.config.redisUrl, {
        enableReadyCheck: true,
        maxRetriesPerRequest: 3,
        lazyConnect: true,
        keepAlive: 30000,
        family: 4,
        db: 0
      } as any);

      this.redisCache.on('error', (error: any) => {
        this.logger.error({ error }, 'Redis cache error');
      });
    }
  }

  private initializeWorkerPool(): void {
    if (this.config.enableWorkerThreads) {
      const workerScript = `
        const { parentPort } = require('worker_threads');
        
        parentPort.on('message', async (data) => {
          try {
            // CPU-intensive task processing
            const result = await processTask(data);
            parentPort.postMessage({ data: result });
          } catch (error) {
            parentPort.postMessage({ error: error.message });
          }
        });
        
        async function processTask(data) {
          // Implement CPU-intensive operations here
          return data;
        }
      `;
      
      this.workerPool = new WorkerThreadPool(
        this.config.workerPoolSize,
        workerScript
      );
    }
  }

  private initializeMonitoring(): void {
    if (this.config.enableMetrics) {
      this.metricsInterval = setInterval(() => {
        this.collectMetrics();
      }, this.config.metricsInterval);
    }
  }

  private optimizeNodeJS(): void {
    // Optimize garbage collection for large heap
    if (process.env.NODE_ENV === 'production') {
      // Set V8 flags for optimal performance with 32GB RAM
      process.env.NODE_OPTIONS = [
        '--max-old-space-size=28672', // 28GB
        '--max-semi-space-size=512',   // 512MB
        '--optimize-for-size',
        '--gc-interval=100',
        '--expose-gc'
      ].join(' ');
    }

    // Force garbage collection when memory threshold is reached
    if (this.config.enableMemoryProfiling) {
      setInterval(() => {
        const memUsage = process.memoryUsage();
        const heapUsedMB = memUsage.heapUsed / 1024 / 1024;
        const heapTotalMB = memUsage.heapTotal / 1024 / 1024;
        const usagePercent = (heapUsedMB / heapTotalMB) * 100;

        if (usagePercent > this.config.gcThreshold && global.gc) {
          global.gc();
          this.logger.info('Forced garbage collection triggered');
        }
      }, 10000);
    }
  }

  // Caching methods
  async get<T>(key: string): Promise<T | null> {
    try {
      // Try LRU cache first
      let value = this.lruCache.get(key);
      if (value !== undefined) {
        this.cacheHits++;
        return value as T;
      }

      // Try Redis cache
      if (this.redisCache) {
        const redisValue = await this.redisCache.get(key);
        if (redisValue) {
          const parsed = JSON.parse(redisValue);
          this.lruCache.set(key, parsed); // Populate LRU cache
          this.cacheHits++;
          return parsed as T;
        }
      }

      this.cacheMisses++;
      return null;
    } catch (error) {
      this.logger.error({ error, key }, 'Cache get error');
      this.cacheMisses++;
      return null;
    }
  }

  async set<T>(key: string, value: T, ttl?: number): Promise<void> {
    try {
      // Set in LRU cache
      this.lruCache.set(key, value, { ttl: (ttl || this.config.cacheTTL) * 1000 });

      // Set in Redis cache
      if (this.redisCache) {
        const serialized = JSON.stringify(value);
        if (ttl) {
          await this.redisCache.setex(key, ttl, serialized);
        } else {
          await this.redisCache.setex(key, this.config.cacheTTL, serialized);
        }
      }
    } catch (error) {
      this.logger.error({ error, key }, 'Cache set error');
    }
  }

  async invalidate(key: string): Promise<void> {
    try {
      this.lruCache.delete(key);
      if (this.redisCache) {
        await this.redisCache.del(key);
      }
    } catch (error) {
      this.logger.error({ error, key }, 'Cache invalidation error');
    }
  }

  async invalidatePattern(pattern: string): Promise<void> {
    try {
      if (this.redisCache) {
        const keys = await this.redisCache.keys(pattern);
        if (keys.length > 0) {
          await this.redisCache.del(...keys);
        }
      }
      
      // For LRU cache, we need to check each key
      for (const key of this.lruCache.keys()) {
        if (key.match(pattern)) {
          this.lruCache.delete(key);
        }
      }
    } catch (error) {
      this.logger.error({ error, pattern }, 'Cache pattern invalidation error');
    }
  }

  // Async task processing
  async processAsync<T>(task: () => Promise<T>): Promise<T> {
    return this.asyncQueue.add(task);
  }

  async processWithWorker<T>(data: any): Promise<T> {
    if (!this.workerPool) {
      throw new Error('Worker pool not initialized');
    }
    return this.workerPool.execute<T>(data);
  }

  // Performance monitoring
  private collectMetrics(): void {
    const cpus = os.cpus();
    const memUsage = process.memoryUsage();
    const loadAvg = os.loadavg();

    this.metrics = {
      timestamp: new Date(),
      cpu: {
        usage: this.calculateCPUUsage(),
        loadAverage: loadAvg,
        cores: cpus.length
      },
      memory: {
        used: memUsage.rss,
        total: os.totalmem(),
        percentage: (memUsage.rss / os.totalmem()) * 100,
        heapUsed: memUsage.heapUsed,
        heapTotal: memUsage.heapTotal
      },
      cache: {
        hitRate: this.cacheHits / (this.cacheHits + this.cacheMisses) * 100 || 0,
        missRate: this.cacheMisses / (this.cacheHits + this.cacheMisses) * 100 || 0,
        size: this.lruCache.size
      },
      requests: {
        total: this.requestCount,
        persecond: this.requestCount / (Date.now() / 1000),
        averageResponseTime: this.responseTimeSum / this.responseTimeCount || 0,
        errorRate: this.errorCount / this.requestCount * 100 || 0
      },
      connections: {
        active: 0, // To be implemented based on actual connections
        waiting: 0,
        pool: {
          db: 0,
          http: 0
        }
      }
    };

    this.emit('metrics', this.metrics);
    this.checkAlerts();
  }

  private calculateCPUUsage(): number {
    // Simple CPU usage calculation
    const cpus = os.cpus();
    let totalIdle = 0;
    let totalTick = 0;

    cpus.forEach(cpu => {
      for (const type in cpu.times) {
        totalTick += cpu.times[type as keyof typeof cpu.times];
      }
      totalIdle += cpu.times.idle;
    });

    return 100 - (totalIdle / totalTick * 100);
  }

  private checkAlerts(): void {
    const { alertThresholds } = this.config;
    
    if (this.metrics.cpu.usage > alertThresholds.cpuUsage) {
      this.emit('alert', {
        type: 'cpu',
        severity: 'warning',
        message: `CPU usage ${this.metrics.cpu.usage.toFixed(1)}% exceeds threshold ${alertThresholds.cpuUsage}%`
      });
    }

    if (this.metrics.memory.percentage > alertThresholds.memoryUsage) {
      this.emit('alert', {
        type: 'memory',
        severity: 'warning',
        message: `Memory usage ${this.metrics.memory.percentage.toFixed(1)}% exceeds threshold ${alertThresholds.memoryUsage}%`
      });
    }

    if (this.metrics.requests.averageResponseTime > alertThresholds.responseTime) {
      this.emit('alert', {
        type: 'response_time',
        severity: 'warning',
        message: `Average response time ${this.metrics.requests.averageResponseTime.toFixed(1)}ms exceeds threshold ${alertThresholds.responseTime}ms`
      });
    }
  }

  // Request tracking
  trackRequest(): void {
    this.requestCount++;
  }

  trackError(): void {
    this.errorCount++;
  }

  trackResponseTime(time: number): void {
    this.responseTimeSum += time;
    this.responseTimeCount++;
  }

  getMetrics(): PerformanceMetrics {
    return this.metrics;
  }

  // Cleanup
  async cleanup(): Promise<void> {
    if (this.metricsInterval) {
      clearInterval(this.metricsInterval);
    }

    if (this.workerPool) {
      this.workerPool.terminate();
    }

    if (this.redisCache) {
      this.redisCache.disconnect();
    }

    this.lruCache.clear();
  }
}

// Utility functions for performance optimization
export function memoize<T extends (...args: any[]) => any>(
  fn: T,
  keyGenerator?: (...args: Parameters<T>) => string
): T {
  const cache = new Map();
  
  return ((...args: Parameters<T>) => {
    const key = keyGenerator ? keyGenerator(...args) : JSON.stringify(args);
    
    if (cache.has(key)) {
      return cache.get(key);
    }
    
    const result = fn(...args);
    cache.set(key, result);
    return result;
  }) as T;
}

export function debounce<T extends (...args: any[]) => any>(
  fn: T,
  delay: number
): T {
  let timeoutId: NodeJS.Timeout;
  
  return ((...args: Parameters<T>) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => fn(...args), delay);
  }) as T;
}

export function throttle<T extends (...args: any[]) => any>(
  fn: T,
  limit: number
): T {
  let inThrottle: boolean;
  
  return ((...args: Parameters<T>) => {
    if (!inThrottle) {
      fn(...args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  }) as T;
}

export function batchAsync<T, R>(
  processor: (items: T[]) => Promise<R[]>,
  batchSize: number = 100,
  delay: number = 50
): (item: T) => Promise<R> {
  const batch: T[] = [];
  const promises: Array<{
    resolve: (value: R) => void;
    reject: (error: any) => void;
  }> = [];
  
  let timeoutId: NodeJS.Timeout;
  
  const processBatch = async () => {
    if (batch.length === 0) return;
    
    const currentBatch = batch.splice(0);
    const currentPromises = promises.splice(0);
    
    try {
      const results = await processor(currentBatch);
      currentPromises.forEach((promise, index) => {
        promise.resolve(results[index]);
      });
    } catch (error) {
      currentPromises.forEach(promise => {
        promise.reject(error);
      });
    }
  };
  
  return (item: T): Promise<R> => {
    return new Promise((resolve, reject) => {
      batch.push(item);
      promises.push({ resolve, reject });
      
      if (batch.length >= batchSize) {
        clearTimeout(timeoutId);
        processBatch();
      } else {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(processBatch, delay);
      }
    });
  };
}