/**
 * Load Balancer for MCP Servers
 * Implements multiple load balancing algorithms optimized for 16-core CPU
 */

import { EventEmitter } from 'events';
import { Logger } from 'pino';
import { PerformanceMetrics } from './performance-optimizer';

export interface LoadBalancerConfig {
  algorithm: 'round-robin' | 'least-connections' | 'weighted-round-robin' | 'least-response-time' | 'resource-based';
  healthCheckInterval: number;
  failureThreshold: number;
  recoveryThreshold: number;
  enableStickySessions: boolean;
  sessionTimeout: number;
  autoScaling: {
    enabled: boolean;
    minInstances: number;
    maxInstances: number;
    scaleUpThreshold: number;
    scaleDownThreshold: number;
    cooldownPeriod: number;
  };
}

export interface ServerInstance {
  id: string;
  host: string;
  port: number;
  weight: number;
  isHealthy: boolean;
  connections: number;
  responseTime: number;
  lastHealthCheck: Date;
  failureCount: number;
  metrics: PerformanceMetrics;
}

export interface LoadBalancingResult {
  server: ServerInstance;
  sessionId?: string;
  loadFactor: number;
}

export interface SessionInfo {
  sessionId: string;
  serverId: string;
  lastAccess: Date;
  stickyUntil: Date;
}

export class LoadBalancer extends EventEmitter {
  private servers: Map<string, ServerInstance> = new Map();
  private sessions: Map<string, SessionInfo> = new Map();
  private config: LoadBalancerConfig;
  private logger: Logger;
  private roundRobinIndex = 0;
  private healthCheckInterval?: NodeJS.Timeout;
  private sessionCleanupInterval?: NodeJS.Timeout;
  private autoScalingInterval?: NodeJS.Timeout;

  constructor(config: LoadBalancerConfig, logger: Logger) {
    super();
    this.config = config;
    this.logger = logger;
    
    this.startHealthChecks();
    this.startSessionCleanup();
    
    if (config.autoScaling.enabled) {
      this.startAutoScaling();
    }
  }

  // Server management
  addServer(server: Omit<ServerInstance, 'isHealthy' | 'connections' | 'responseTime' | 'lastHealthCheck' | 'failureCount' | 'metrics'>): void {
    const serverInstance: ServerInstance = {
      ...server,
      isHealthy: true,
      connections: 0,
      responseTime: 0,
      lastHealthCheck: new Date(),
      failureCount: 0,
      metrics: {} as PerformanceMetrics
    };

    this.servers.set(server.id, serverInstance);
    this.logger.info({ serverId: server.id, host: server.host, port: server.port }, 'Server added to load balancer');
    this.emit('server-added', serverInstance);
  }

  removeServer(serverId: string): void {
    const server = this.servers.get(serverId);
    if (server) {
      this.servers.delete(serverId);
      this.logger.info({ serverId }, 'Server removed from load balancer');
      this.emit('server-removed', server);
    }
  }

  updateServerMetrics(serverId: string, metrics: PerformanceMetrics): void {
    const server = this.servers.get(serverId);
    if (server) {
      server.metrics = metrics;
      server.lastHealthCheck = new Date();
    }
  }

  updateServerHealth(serverId: string, isHealthy: boolean, responseTime: number = 0): void {
    const server = this.servers.get(serverId);
    if (server) {
      const wasHealthy = server.isHealthy;
      server.isHealthy = isHealthy;
      server.responseTime = responseTime;
      server.lastHealthCheck = new Date();

      if (isHealthy) {
        server.failureCount = 0;
        if (!wasHealthy) {
          this.logger.info({ serverId }, 'Server recovered');
          this.emit('server-recovered', server);
        }
      } else {
        server.failureCount++;
        if (wasHealthy) {
          this.logger.warn({ serverId }, 'Server marked unhealthy');
          this.emit('server-failed', server);
        }
      }
    }
  }

  // Load balancing algorithms
  selectServer(sessionId?: string): LoadBalancingResult | null {
    const healthyServers = Array.from(this.servers.values()).filter(s => s.isHealthy);
    
    if (healthyServers.length === 0) {
      this.logger.error('No healthy servers available');
      return null;
    }

    // Check for sticky session
    if (sessionId && this.config.enableStickySessions) {
      const session = this.sessions.get(sessionId);
      if (session && session.stickyUntil > new Date()) {
        const server = this.servers.get(session.serverId);
        if (server && server.isHealthy) {
          this.updateSessionAccess(sessionId);
          return {
            server,
            sessionId,
            loadFactor: this.calculateLoadFactor(server)
          };
        }
      }
    }

    let selectedServer: ServerInstance;

    switch (this.config.algorithm) {
      case 'round-robin':
        selectedServer = this.roundRobinSelection(healthyServers);
        break;
      case 'least-connections':
        selectedServer = this.leastConnectionsSelection(healthyServers);
        break;
      case 'weighted-round-robin':
        selectedServer = this.weightedRoundRobinSelection(healthyServers);
        break;
      case 'least-response-time':
        selectedServer = this.leastResponseTimeSelection(healthyServers);
        break;
      case 'resource-based':
        selectedServer = this.resourceBasedSelection(healthyServers);
        break;
      default:
        selectedServer = this.roundRobinSelection(healthyServers);
    }

    // Create or update session if sticky sessions are enabled
    let finalSessionId = sessionId;
    if (this.config.enableStickySessions && !sessionId) {
      finalSessionId = this.generateSessionId();
      this.createSession(finalSessionId, selectedServer.id);
    } else if (this.config.enableStickySessions && sessionId) {
      this.updateSession(sessionId, selectedServer.id);
    }

    return {
      server: selectedServer,
      sessionId: finalSessionId,
      loadFactor: this.calculateLoadFactor(selectedServer)
    };
  }

  private roundRobinSelection(servers: ServerInstance[]): ServerInstance {
    const server = servers[this.roundRobinIndex % servers.length];
    this.roundRobinIndex = (this.roundRobinIndex + 1) % servers.length;
    return server;
  }

  private leastConnectionsSelection(servers: ServerInstance[]): ServerInstance {
    return servers.reduce((min, server) => 
      server.connections < min.connections ? server : min
    );
  }

  private weightedRoundRobinSelection(servers: ServerInstance[]): ServerInstance {
    const totalWeight = servers.reduce((sum, server) => sum + server.weight, 0);
    let randomWeight = Math.random() * totalWeight;
    
    for (const server of servers) {
      randomWeight -= server.weight;
      if (randomWeight <= 0) {
        return server;
      }
    }
    
    return servers[0]; // Fallback
  }

  private leastResponseTimeSelection(servers: ServerInstance[]): ServerInstance {
    return servers.reduce((min, server) => 
      server.responseTime < min.responseTime ? server : min
    );
  }

  private resourceBasedSelection(servers: ServerInstance[]): ServerInstance {
    // Score based on CPU, memory, and connection load
    const scoredServers = servers.map(server => {
      const cpuScore = server.metrics.cpu ? (100 - server.metrics.cpu.usage) : 50;
      const memoryScore = server.metrics.memory ? (100 - server.metrics.memory.percentage) : 50;
      const connectionScore = Math.max(0, 100 - (server.connections * 10));
      const responseTimeScore = Math.max(0, 100 - (server.responseTime / 10));
      
      const totalScore = (cpuScore + memoryScore + connectionScore + responseTimeScore) / 4;
      
      return { server, score: totalScore };
    });

    return scoredServers.reduce((best, current) => 
      current.score > best.score ? current : best
    ).server;
  }

  private calculateLoadFactor(server: ServerInstance): number {
    const maxConnections = 1000; // Configurable max
    const connectionFactor = server.connections / maxConnections;
    const responseTimeFactor = Math.min(server.responseTime / 1000, 1); // Normalize to 0-1
    const cpuFactor = server.metrics.cpu ? server.metrics.cpu.usage / 100 : 0;
    const memoryFactor = server.metrics.memory ? server.metrics.memory.percentage / 100 : 0;
    
    return (connectionFactor + responseTimeFactor + cpuFactor + memoryFactor) / 4;
  }

  // Session management
  private generateSessionId(): string {
    return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private createSession(sessionId: string, serverId: string): void {
    const stickyUntil = new Date(Date.now() + this.config.sessionTimeout);
    this.sessions.set(sessionId, {
      sessionId,
      serverId,
      lastAccess: new Date(),
      stickyUntil
    });
  }

  private updateSession(sessionId: string, serverId: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.serverId = serverId;
      session.lastAccess = new Date();
      session.stickyUntil = new Date(Date.now() + this.config.sessionTimeout);
    } else {
      this.createSession(sessionId, serverId);
    }
  }

  private updateSessionAccess(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.lastAccess = new Date();
    }
  }

  // Connection tracking
  incrementConnection(serverId: string): void {
    const server = this.servers.get(serverId);
    if (server) {
      server.connections++;
      this.emit('connection-increment', server);
    }
  }

  decrementConnection(serverId: string): void {
    const server = this.servers.get(serverId);
    if (server) {
      server.connections = Math.max(0, server.connections - 1);
      this.emit('connection-decrement', server);
    }
  }

  // Health monitoring
  private startHealthChecks(): void {
    this.healthCheckInterval = setInterval(async () => {
      await this.performHealthChecks();
    }, this.config.healthCheckInterval);
  }

  private async performHealthChecks(): Promise<void> {
    const healthCheckPromises = Array.from(this.servers.values()).map(async (server) => {
      try {
        const startTime = Date.now();
        
        // Perform health check (implement actual health check logic)
        const isHealthy = await this.checkServerHealth(server);
        const responseTime = Date.now() - startTime;
        
        this.updateServerHealth(server.id, isHealthy, responseTime);
      } catch (error) {
        this.logger.error({ error, serverId: server.id }, 'Health check failed');
        this.updateServerHealth(server.id, false);
      }
    });

    await Promise.allSettled(healthCheckPromises);
  }

  private async checkServerHealth(server: ServerInstance): Promise<boolean> {
    // Implement actual health check logic here
    // This could be an HTTP request, TCP connection, or custom health endpoint
    
    // For now, return true if failure count is below threshold
    return server.failureCount < this.config.failureThreshold;
  }

  // Session cleanup
  private startSessionCleanup(): void {
    this.sessionCleanupInterval = setInterval(() => {
      this.cleanupExpiredSessions();
    }, 60000); // Clean up every minute
  }

  private cleanupExpiredSessions(): void {
    const now = new Date();
    const expiredSessions: string[] = [];

    for (const [sessionId, session] of this.sessions) {
      if (session.stickyUntil < now) {
        expiredSessions.push(sessionId);
      }
    }

    expiredSessions.forEach(sessionId => {
      this.sessions.delete(sessionId);
    });

    if (expiredSessions.length > 0) {
      this.logger.debug({ count: expiredSessions.length }, 'Cleaned up expired sessions');
    }
  }

  // Auto-scaling
  private startAutoScaling(): void {
    this.autoScalingInterval = setInterval(() => {
      this.evaluateAutoScaling();
    }, this.config.autoScaling.cooldownPeriod);
  }

  private evaluateAutoScaling(): void {
    const healthyServers = Array.from(this.servers.values()).filter(s => s.isHealthy);
    const currentLoad = this.calculateOverallLoad();

    if (currentLoad > this.config.autoScaling.scaleUpThreshold && 
        healthyServers.length < this.config.autoScaling.maxInstances) {
      this.emit('scale-up-needed', { currentLoad, serverCount: healthyServers.length });
      this.logger.info({ currentLoad, serverCount: healthyServers.length }, 'Scale up needed');
    } else if (currentLoad < this.config.autoScaling.scaleDownThreshold && 
               healthyServers.length > this.config.autoScaling.minInstances) {
      this.emit('scale-down-needed', { currentLoad, serverCount: healthyServers.length });
      this.logger.info({ currentLoad, serverCount: healthyServers.length }, 'Scale down possible');
    }
  }

  private calculateOverallLoad(): number {
    const healthyServers = Array.from(this.servers.values()).filter(s => s.isHealthy);
    
    if (healthyServers.length === 0) return 100;

    const totalLoad = healthyServers.reduce((sum, server) => 
      sum + this.calculateLoadFactor(server), 0
    );

    return (totalLoad / healthyServers.length) * 100;
  }

  // Statistics and monitoring
  getStatistics(): {
    servers: { total: number; healthy: number; unhealthy: number };
    connections: { total: number; average: number };
    sessions: { active: number; total: number };
    load: { overall: number; byServer: { [serverId: string]: number } };
  } {
    const servers = Array.from(this.servers.values());
    const healthyServers = servers.filter(s => s.isHealthy);
    const totalConnections = servers.reduce((sum, s) => sum + s.connections, 0);

    return {
      servers: {
        total: servers.length,
        healthy: healthyServers.length,
        unhealthy: servers.length - healthyServers.length
      },
      connections: {
        total: totalConnections,
        average: servers.length > 0 ? totalConnections / servers.length : 0
      },
      sessions: {
        active: this.sessions.size,
        total: this.sessions.size
      },
      load: {
        overall: this.calculateOverallLoad(),
        byServer: Object.fromEntries(
          servers.map(server => [server.id, this.calculateLoadFactor(server) * 100])
        )
      }
    };
  }

  getServerList(): ServerInstance[] {
    return Array.from(this.servers.values());
  }

  getHealthyServers(): ServerInstance[] {
    return Array.from(this.servers.values()).filter(s => s.isHealthy);
  }

  // Cleanup
  destroy(): void {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }

    if (this.sessionCleanupInterval) {
      clearInterval(this.sessionCleanupInterval);
    }

    if (this.autoScalingInterval) {
      clearInterval(this.autoScalingInterval);
    }

    this.servers.clear();
    this.sessions.clear();
    this.logger.info('Load balancer destroyed');
  }
}

// Load balancer factory for easy configuration
export function createLoadBalancer(
  algorithm: LoadBalancerConfig['algorithm'] = 'resource-based',
  options: Partial<LoadBalancerConfig> = {},
  logger: Logger
): LoadBalancer {
  const defaultConfig: LoadBalancerConfig = {
    algorithm,
    healthCheckInterval: 10000, // 10 seconds
    failureThreshold: 3,
    recoveryThreshold: 2,
    enableStickySessions: true,
    sessionTimeout: 300000, // 5 minutes
    autoScaling: {
      enabled: true,
      minInstances: 2,
      maxInstances: 16, // Match CPU cores
      scaleUpThreshold: 80,
      scaleDownThreshold: 30,
      cooldownPeriod: 300000 // 5 minutes
    }
  };

  const config = { ...defaultConfig, ...options };
  return new LoadBalancer(config, logger);
}