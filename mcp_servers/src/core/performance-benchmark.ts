/**
 * Performance Benchmark Suite for MCP Servers
 * Comprehensive benchmarking and optimization validation
 */

import { EventEmitter } from 'events';
import { Logger } from 'pino';
import { OptimizedMCPServer } from './optimized-base-server';
import { PerformanceMetrics } from './performance-optimizer';
import { Worker } from 'worker_threads';
import os from 'os';
import { promisify } from 'util';

export interface BenchmarkConfig {
  duration: number; // Test duration in seconds
  warmupDuration: number; // Warmup duration in seconds
  concurrency: number; // Number of concurrent operations
  requestsPerSecond: number; // Target RPS
  scenarios: BenchmarkScenario[];
}

export interface BenchmarkScenario {
  name: string;
  weight: number; // Relative weight (1-100)
  operation: () => Promise<any>;
  validation?: (result: any) => boolean;
}

export interface BenchmarkResult {
  scenario: string;
  startTime: Date;
  endTime: Date;
  duration: number;
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  requestsPerSecond: number;
  averageResponseTime: number;
  medianResponseTime: number;
  p95ResponseTime: number;
  p99ResponseTime: number;
  minResponseTime: number;
  maxResponseTime: number;
  errorRate: number;
  throughput: number;
  memoryUsage: {
    initial: number;
    peak: number;
    final: number;
  };
  cpuUsage: {
    average: number;
    peak: number;
  };
}

export interface BenchmarkReport {
  config: BenchmarkConfig;
  startTime: Date;
  endTime: Date;
  totalDuration: number;
  scenarios: BenchmarkResult[];
  summary: {
    totalRequests: number;
    totalSuccessful: number;
    totalFailed: number;
    overallRPS: number;
    overallErrorRate: number;
    averageResponseTime: number;
    p99ResponseTime: number;
  };
  systemInfo: {
    cpuCores: number;
    totalMemory: number;
    nodeVersion: string;
    platform: string;
    arch: string;
  };
  optimizationEffectiveness: {
    cacheHitRate: number;
    connectionPoolUtilization: number;
    workerThreadUtilization: number;
    memoryEfficiency: number;
  };
  recommendations: string[];
}

export class PerformanceBenchmark extends EventEmitter {
  private logger: Logger;
  private server: OptimizedMCPServer;
  private isRunning = false;

  constructor(server: OptimizedMCPServer, logger: Logger) {
    super();
    this.server = server;
    this.logger = logger;
  }

  async runBenchmark(config: BenchmarkConfig): Promise<BenchmarkReport> {
    if (this.isRunning) {
      throw new Error('Benchmark is already running');
    }

    this.isRunning = true;
    this.logger.info({ config }, 'Starting performance benchmark');

    const report: BenchmarkReport = {
      config,
      startTime: new Date(),
      endTime: new Date(),
      totalDuration: 0,
      scenarios: [],
      summary: {
        totalRequests: 0,
        totalSuccessful: 0,
        totalFailed: 0,
        overallRPS: 0,
        overallErrorRate: 0,
        averageResponseTime: 0,
        p99ResponseTime: 0
      },
      systemInfo: {
        cpuCores: os.cpus().length,
        totalMemory: os.totalmem(),
        nodeVersion: process.version,
        platform: os.platform(),
        arch: os.arch()
      },
      optimizationEffectiveness: {
        cacheHitRate: 0,
        connectionPoolUtilization: 0,
        workerThreadUtilization: 0,
        memoryEfficiency: 0
      },
      recommendations: []
    };

    try {
      // Warmup phase
      if (config.warmupDuration > 0) {
        await this.runWarmup(config);
      }

      // Run benchmark scenarios
      for (const scenario of config.scenarios) {
        const result = await this.runScenario(scenario, config);
        report.scenarios.push(result);
        this.emit('scenario-complete', result);
      }

      // Calculate summary metrics
      report.summary = this.calculateSummary(report.scenarios);
      report.endTime = new Date();
      report.totalDuration = report.endTime.getTime() - report.startTime.getTime();

      // Analyze optimization effectiveness
      report.optimizationEffectiveness = await this.analyzeOptimizations();

      // Generate recommendations
      report.recommendations = this.generateRecommendations(report);

      this.logger.info({ report: report.summary }, 'Benchmark completed');
      this.emit('benchmark-complete', report);

      return report;

    } finally {
      this.isRunning = false;
    }
  }

  private async runWarmup(config: BenchmarkConfig): Promise<void> {
    this.logger.info({ duration: config.warmupDuration }, 'Starting warmup phase');

    const warmupPromises: Promise<any>[] = [];
    const warmupEnd = Date.now() + (config.warmupDuration * 1000);

    while (Date.now() < warmupEnd) {
      const scenario = this.selectRandomScenario(config.scenarios);
      warmupPromises.push(
        scenario.operation().catch(() => {}) // Ignore errors during warmup
      );

      // Control rate
      await this.sleep(1000 / config.requestsPerSecond);
    }

    await Promise.allSettled(warmupPromises);
    this.logger.info('Warmup phase completed');
  }

  private async runScenario(scenario: BenchmarkScenario, config: BenchmarkConfig): Promise<BenchmarkResult> {
    this.logger.info({ scenario: scenario.name }, 'Starting scenario benchmark');

    const result: BenchmarkResult = {
      scenario: scenario.name,
      startTime: new Date(),
      endTime: new Date(),
      duration: 0,
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      requestsPerSecond: 0,
      averageResponseTime: 0,
      medianResponseTime: 0,
      p95ResponseTime: 0,
      p99ResponseTime: 0,
      minResponseTime: Infinity,
      maxResponseTime: 0,
      errorRate: 0,
      throughput: 0,
      memoryUsage: {
        initial: process.memoryUsage().heapUsed,
        peak: process.memoryUsage().heapUsed,
        final: 0
      },
      cpuUsage: {
        average: 0,
        peak: 0
      }
    };

    const responseTimes: number[] = [];
    const requests: Promise<void>[] = [];
    const testEnd = Date.now() + (config.duration * 1000);
    const requestInterval = 1000 / config.requestsPerSecond;

    // CPU monitoring
    const cpuUsages: number[] = [];
    const cpuMonitor = setInterval(() => {
      const usage = this.getCPUUsage();
      cpuUsages.push(usage);
      result.cpuUsage.peak = Math.max(result.cpuUsage.peak, usage);
    }, 100);

    let requestCounter = 0;

    while (Date.now() < testEnd) {
      const requestPromise = this.executeRequest(scenario, result, responseTimes);
      requests.push(requestPromise);
      
      requestCounter++;
      result.totalRequests = requestCounter;

      // Control concurrency
      if (requests.length >= config.concurrency) {
        await Promise.race(requests);
        // Remove completed requests
        for (let i = requests.length - 1; i >= 0; i--) {
          if (await this.isPromiseResolved(requests[i])) {
            requests.splice(i, 1);
          }
        }
      }

      // Monitor memory
      const currentMemory = process.memoryUsage().heapUsed;
      result.memoryUsage.peak = Math.max(result.memoryUsage.peak, currentMemory);

      // Control rate
      await this.sleep(requestInterval);
    }

    // Wait for remaining requests
    await Promise.allSettled(requests);

    clearInterval(cpuMonitor);

    // Calculate final metrics
    result.endTime = new Date();
    result.duration = result.endTime.getTime() - result.startTime.getTime();
    result.memoryUsage.final = process.memoryUsage().heapUsed;
    result.cpuUsage.average = cpuUsages.reduce((a, b) => a + b, 0) / cpuUsages.length;

    if (responseTimes.length > 0) {
      responseTimes.sort((a, b) => a - b);
      result.averageResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
      result.medianResponseTime = responseTimes[Math.floor(responseTimes.length / 2)];
      result.p95ResponseTime = responseTimes[Math.floor(responseTimes.length * 0.95)];
      result.p99ResponseTime = responseTimes[Math.floor(responseTimes.length * 0.99)];
      result.minResponseTime = responseTimes[0];
      result.maxResponseTime = responseTimes[responseTimes.length - 1];
    }

    result.requestsPerSecond = result.totalRequests / (result.duration / 1000);
    result.errorRate = (result.failedRequests / result.totalRequests) * 100;
    result.throughput = result.successfulRequests / (result.duration / 1000);

    this.logger.info({ 
      scenario: scenario.name,
      rps: result.requestsPerSecond,
      errorRate: result.errorRate,
      avgResponseTime: result.averageResponseTime
    }, 'Scenario completed');

    return result;
  }

  private async executeRequest(
    scenario: BenchmarkScenario,
    result: BenchmarkResult,
    responseTimes: number[]
  ): Promise<void> {
    const startTime = Date.now();

    try {
      const response = await scenario.operation();
      
      const responseTime = Date.now() - startTime;
      responseTimes.push(responseTime);
      
      // Validate response if validator provided
      if (scenario.validation && !scenario.validation(response)) {
        result.failedRequests++;
      } else {
        result.successfulRequests++;
      }

    } catch (error) {
      result.failedRequests++;
      this.logger.debug({ error, scenario: scenario.name }, 'Request failed');
    }
  }

  private selectRandomScenario(scenarios: BenchmarkScenario[]): BenchmarkScenario {
    const totalWeight = scenarios.reduce((sum, s) => sum + s.weight, 0);
    let random = Math.random() * totalWeight;

    for (const scenario of scenarios) {
      random -= scenario.weight;
      if (random <= 0) {
        return scenario;
      }
    }

    return scenarios[0]; // Fallback
  }

  private calculateSummary(scenarios: BenchmarkResult[]): BenchmarkReport['summary'] {
    const summary = {
      totalRequests: 0,
      totalSuccessful: 0,
      totalFailed: 0,
      overallRPS: 0,
      overallErrorRate: 0,
      averageResponseTime: 0,
      p99ResponseTime: 0
    };

    if (scenarios.length === 0) return summary;

    const totalDuration = scenarios.reduce((max, s) => Math.max(max, s.duration), 0);
    let totalResponseTime = 0;
    let totalResponseCount = 0;
    const allP99s: number[] = [];

    for (const scenario of scenarios) {
      summary.totalRequests += scenario.totalRequests;
      summary.totalSuccessful += scenario.successfulRequests;
      summary.totalFailed += scenario.failedRequests;
      totalResponseTime += scenario.averageResponseTime * scenario.successfulRequests;
      totalResponseCount += scenario.successfulRequests;
      allP99s.push(scenario.p99ResponseTime);
    }

    summary.overallRPS = summary.totalRequests / (totalDuration / 1000);
    summary.overallErrorRate = (summary.totalFailed / summary.totalRequests) * 100;
    summary.averageResponseTime = totalResponseTime / totalResponseCount;
    summary.p99ResponseTime = Math.max(...allP99s);

    return summary;
  }

  private async analyzeOptimizations(): Promise<BenchmarkReport['optimizationEffectiveness']> {
    const effectiveness = {
      cacheHitRate: 0,
      connectionPoolUtilization: 0,
      workerThreadUtilization: 0,
      memoryEfficiency: 0
    };

    try {
      const performanceMetrics = this.server.getPerformanceMetrics();
      const connectionMetrics = this.server.getConnectionMetrics();

      // Cache effectiveness
      if (performanceMetrics.cache) {
        effectiveness.cacheHitRate = performanceMetrics.cache.hitRate;
      }

      // Connection pool utilization
      const poolMetrics = Object.values(connectionMetrics);
      if (poolMetrics.length > 0) {
        effectiveness.connectionPoolUtilization = 
          poolMetrics.reduce((sum, pool) => sum + pool.utilizationRate, 0) / poolMetrics.length;
      }

      // Worker thread utilization (estimated based on CPU usage)
      if (performanceMetrics.cpu) {
        effectiveness.workerThreadUtilization = Math.min(performanceMetrics.cpu.usage, 100);
      }

      // Memory efficiency (how well memory is being utilized vs wasted)
      if (performanceMetrics.memory) {
        const heapUtilization = (performanceMetrics.memory.heapUsed / performanceMetrics.memory.heapTotal) * 100;
        effectiveness.memoryEfficiency = heapUtilization;
      }

    } catch (error) {
      this.logger.error({ error }, 'Failed to analyze optimizations');
    }

    return effectiveness;
  }

  private generateRecommendations(report: BenchmarkReport): string[] {
    const recommendations: string[] = [];
    const { summary, optimizationEffectiveness, scenarios } = report;

    // Error rate recommendations
    if (summary.overallErrorRate > 5) {
      recommendations.push(`High error rate (${summary.overallErrorRate.toFixed(1)}%). Consider implementing circuit breakers and better error handling.`);
    }

    // Response time recommendations
    if (summary.averageResponseTime > 1000) {
      recommendations.push(`High average response time (${summary.averageResponseTime.toFixed(1)}ms). Consider optimizing database queries and enabling more aggressive caching.`);
    }

    // Cache effectiveness
    if (optimizationEffectiveness.cacheHitRate < 80) {
      recommendations.push(`Low cache hit rate (${optimizationEffectiveness.cacheHitRate.toFixed(1)}%). Review caching strategy and TTL settings.`);
    }

    // Connection pool utilization
    if (optimizationEffectiveness.connectionPoolUtilization > 90) {
      recommendations.push(`High connection pool utilization (${optimizationEffectiveness.connectionPoolUtilization.toFixed(1)}%). Consider increasing pool size.`);
    } else if (optimizationEffectiveness.connectionPoolUtilization < 30) {
      recommendations.push(`Low connection pool utilization (${optimizationEffectiveness.connectionPoolUtilization.toFixed(1)}%). Consider reducing pool size to save resources.`);
    }

    // Memory efficiency
    if (optimizationEffectiveness.memoryEfficiency > 90) {
      recommendations.push(`High memory usage (${optimizationEffectiveness.memoryEfficiency.toFixed(1)}%). Consider implementing memory-based auto-scaling or increasing heap size.`);
    }

    // CPU utilization
    if (optimizationEffectiveness.workerThreadUtilization > 85) {
      recommendations.push(`High CPU utilization (${optimizationEffectiveness.workerThreadUtilization.toFixed(1)}%). Consider horizontal scaling or optimizing CPU-intensive operations.`);
    }

    // Throughput recommendations
    const expectedRPS = report.config.requestsPerSecond;
    if (summary.overallRPS < expectedRPS * 0.8) {
      recommendations.push(`Actual RPS (${summary.overallRPS.toFixed(1)}) is significantly lower than target (${expectedRPS}). Review bottlenecks and scaling configuration.`);
    }

    // Scenario-specific recommendations
    const slowScenarios = scenarios.filter(s => s.averageResponseTime > 2000);
    if (slowScenarios.length > 0) {
      recommendations.push(`Slow scenarios detected: ${slowScenarios.map(s => s.scenario).join(', ')}. Focus optimization efforts on these operations.`);
    }

    if (recommendations.length === 0) {
      recommendations.push('Performance looks good! No immediate optimizations needed.');
    }

    return recommendations;
  }

  private getCPUUsage(): number {
    // Simple CPU usage calculation (you might want to use a more sophisticated method)
    const loadAverage = os.loadavg()[0];
    const cpuCores = os.cpus().length;
    return Math.min((loadAverage / cpuCores) * 100, 100);
  }

  private async isPromiseResolved(promise: Promise<any>): Promise<boolean> {
    try {
      const result = await Promise.race([
        promise,
        new Promise(resolve => setTimeout(() => resolve('timeout'), 0))
      ]);
      return result !== 'timeout';
    } catch {
      return true; // Rejected promises are also "resolved"
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Pre-built benchmark scenarios
  static createStandardScenarios(server: OptimizedMCPServer): BenchmarkScenario[] {
    return [
      {
        name: 'list-tools',
        weight: 30,
        operation: async () => {
          // Simulate listing tools
          return { tools: ['tool1', 'tool2', 'tool3'] };
        },
        validation: (result) => Array.isArray(result.tools)
      },
      {
        name: 'tool-execution',
        weight: 50,
        operation: async () => {
          // Simulate tool execution
          await new Promise(resolve => setTimeout(resolve, Math.random() * 100));
          return { result: 'success', data: Math.random() };
        },
        validation: (result) => result.result === 'success'
      },
      {
        name: 'resource-read',
        weight: 20,
        operation: async () => {
          // Simulate resource reading
          await new Promise(resolve => setTimeout(resolve, Math.random() * 50));
          return { content: 'resource data', size: Math.random() * 1000 };
        },
        validation: (result) => typeof result.content === 'string'
      }
    ];
  }

  // Load testing utilities
  static async runLoadTest(
    server: OptimizedMCPServer,
    logger: Logger,
    options: {
      duration?: number;
      concurrency?: number;
      targetRPS?: number;
    } = {}
  ): Promise<BenchmarkReport> {
    const benchmark = new PerformanceBenchmark(server, logger);
    
    const config: BenchmarkConfig = {
      duration: options.duration || 60,
      warmupDuration: 10,
      concurrency: options.concurrency || 50,
      requestsPerSecond: options.targetRPS || 1000,
      scenarios: PerformanceBenchmark.createStandardScenarios(server)
    };

    return benchmark.runBenchmark(config);
  }

  // Stress testing
  static async runStressTest(
    server: OptimizedMCPServer,
    logger: Logger,
    options: {
      maxConcurrency?: number;
      duration?: number;
    } = {}
  ): Promise<BenchmarkReport[]> {
    const results: BenchmarkReport[] = [];
    const maxConcurrency = options.maxConcurrency || 500;
    const duration = options.duration || 30;
    
    // Gradually increase load
    for (let concurrency = 10; concurrency <= maxConcurrency; concurrency *= 2) {
      logger.info({ concurrency }, 'Running stress test phase');
      
      const result = await PerformanceBenchmark.runLoadTest(server, logger, {
        duration,
        concurrency,
        targetRPS: concurrency * 10
      });
      
      results.push(result);
      
      // Stop if error rate becomes too high
      if (result.summary.overallErrorRate > 20) {
        logger.warn('High error rate detected, stopping stress test');
        break;
      }
    }
    
    return results;
  }
}