/**
 * Service Discovery and Registry System
 * 
 * Provides service registration, discovery, and health monitoring
 * for distributed MCP server deployments.
 */

import { EventEmitter } from 'events';
import { ServiceRegistry, ServiceInfo, LoadBalancer, HealthStatus } from '../core/interfaces';
import { createEnhancedLogger, MCPLogger } from '../core/logger';
import { createHealthCheck } from '../core/utils';

// ============================================================================
// In-Memory Service Registry Implementation
// ============================================================================

export class InMemoryServiceRegistry extends EventEmitter implements ServiceRegistry {
  private services: Map<string, ServiceInfo> = new Map();
  private watchers: Map<string, Array<(services: ServiceInfo[]) => void>> = new Map();
  private logger: MCPLogger;
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor() {
    super();
    this.logger = createEnhancedLogger('service-registry');
    this.startCleanupTask();
  }

  public async register(service: ServiceInfo): Promise<void> {
    // Validate service info
    this.validateServiceInfo(service);

    // Update last seen time
    service.lastSeen = new Date();
    service.registeredAt = service.registeredAt || new Date();

    const existingService = this.services.get(service.id);
    this.services.set(service.id, service);

    if (existingService) {
      this.logger.info(`Service updated: ${service.name} (${service.id})`, { 
        endpoint: service.endpoint,
        version: service.version 
      });
      this.emit('service_updated', service, existingService);
    } else {
      this.logger.info(`Service registered: ${service.name} (${service.id})`, { 
        endpoint: service.endpoint,
        version: service.version 
      });
      this.emit('service_registered', service);
    }

    // Notify watchers
    this.notifyWatchers(service.type);
  }

  public async unregister(serviceId: string): Promise<void> {
    const service = this.services.get(serviceId);
    if (service) {
      this.services.delete(serviceId);
      this.logger.info(`Service unregistered: ${service.name} (${serviceId})`);
      this.emit('service_unregistered', service);
      this.notifyWatchers(service.type);
    }
  }

  public async discover(serviceType: string): Promise<ServiceInfo[]> {
    const services = Array.from(this.services.values())
      .filter(service => service.type === serviceType)
      .filter(service => this.isServiceHealthy(service))
      .sort((a, b) => b.lastSeen.getTime() - a.lastSeen.getTime());

    this.logger.debug(`Discovered ${services.length} services of type: ${serviceType}`);
    return services;
  }

  public watch(serviceType: string, callback: (services: ServiceInfo[]) => void): void {
    if (!this.watchers.has(serviceType)) {
      this.watchers.set(serviceType, []);
    }
    this.watchers.get(serviceType)!.push(callback);

    // Immediately notify with current services
    this.discover(serviceType).then(callback);
    
    this.logger.debug(`Watcher added for service type: ${serviceType}`);
  }

  public unwatch(serviceType: string, callback: (services: ServiceInfo[]) => void): void {
    const watchers = this.watchers.get(serviceType);
    if (watchers) {
      const index = watchers.indexOf(callback);
      if (index > -1) {
        watchers.splice(index, 1);
        this.logger.debug(`Watcher removed for service type: ${serviceType}`);
      }
    }
  }

  public async getService(serviceId: string): Promise<ServiceInfo | null> {
    return this.services.get(serviceId) || null;
  }

  public async listServices(): Promise<ServiceInfo[]> {
    return Array.from(this.services.values());
  }

  public async getServicesByTag(tag: string): Promise<ServiceInfo[]> {
    return Array.from(this.services.values())
      .filter(service => service.tags.includes(tag));
  }

  public async updateHealth(serviceId: string, health: HealthStatus): Promise<void> {
    const service = this.services.get(serviceId);
    if (service) {
      service.health = health;
      service.lastSeen = new Date();
      this.emit('service_health_updated', service);
      this.notifyWatchers(service.type);
    }
  }

  private validateServiceInfo(service: ServiceInfo): void {
    if (!service.id || !service.name || !service.type || !service.endpoint) {
      throw new Error('Service must have id, name, type, and endpoint');
    }

    try {
      new URL(service.endpoint);
    } catch {
      throw new Error('Service endpoint must be a valid URL');
    }
  }

  private isServiceHealthy(service: ServiceInfo): boolean {
    // Check if service is healthy and not stale
    const isHealthy = service.health === HealthStatus.HEALTHY || service.health === HealthStatus.DEGRADED;
    const isNotStale = Date.now() - service.lastSeen.getTime() < 60000; // 1 minute
    return isHealthy && isNotStale;
  }

  private notifyWatchers(serviceType: string): void {
    const watchers = this.watchers.get(serviceType);
    if (watchers) {
      this.discover(serviceType).then(services => {
        watchers.forEach(callback => {
          try {
            callback(services);
          } catch (error) {
            this.logger.error("Service error:", { serviceType });
          }
        });
      });
    }
  }

  private startCleanupTask(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanupStaleServices();
    }, 30000); // Run every 30 seconds
  }

  private cleanupStaleServices(): void {
    const now = Date.now();
    const staleThreshold = 5 * 60 * 1000; // 5 minutes
    const stalServices: string[] = [];

    for (const [id, service] of this.services) {
      if (now - service.lastSeen.getTime() > staleThreshold) {
        stalServices.push(id);
      }
    }

    for (const id of stalServices) {
      this.unregister(id);
    }

    if (stalServices.length > 0) {
      this.logger.info(`Cleaned up ${stalServices.length} stale services`);
    }
  }

  public dispose(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    this.removeAllListeners();
  }
}

// ============================================================================
// Load Balancer Implementations
// ============================================================================

export class RoundRobinLoadBalancer implements LoadBalancer {
  private currentIndex = 0;
  private weights: Map<string, number> = new Map();

  public selectService(services: ServiceInfo[]): ServiceInfo | null {
    if (services.length === 0) {
      return null;
    }

    const service = services[this.currentIndex % services.length];
    this.currentIndex = (this.currentIndex + 1) % services.length;
    return service;
  }

  public updateWeights(weights: Record<string, number>): void {
    this.weights.clear();
    for (const [serviceId, weight] of Object.entries(weights)) {
      this.weights.set(serviceId, weight);
    }
  }
}

export class WeightedRoundRobinLoadBalancer implements LoadBalancer {
  private currentWeights: Map<string, number> = new Map();
  private weights: Map<string, number> = new Map();

  public selectService(services: ServiceInfo[]): ServiceInfo | null {
    if (services.length === 0) {
      return null;
    }

    if (services.length === 1) {
      return services[0];
    }

    let selectedService: ServiceInfo | null = null;
    let maxCurrentWeight = -1;

    for (const service of services) {
      const weight = this.weights.get(service.id) || 1;
      const currentWeight = this.currentWeights.get(service.id) || 0;
      
      const newCurrentWeight = currentWeight + weight;
      this.currentWeights.set(service.id, newCurrentWeight);

      if (newCurrentWeight > maxCurrentWeight) {
        maxCurrentWeight = newCurrentWeight;
        selectedService = service;
      }
    }

    if (selectedService) {
      const totalWeight = services.reduce((sum, service) => 
        sum + (this.weights.get(service.id) || 1), 0);
      const currentWeight = this.currentWeights.get(selectedService.id) || 0;
      this.currentWeights.set(selectedService.id, currentWeight - totalWeight);
    }

    return selectedService;
  }

  public updateWeights(weights: Record<string, number>): void {
    this.weights.clear();
    for (const [serviceId, weight] of Object.entries(weights)) {
      this.weights.set(serviceId, Math.max(1, weight)); // Ensure minimum weight of 1
    }
  }
}

export class LeastConnectionsLoadBalancer implements LoadBalancer {
  private connections: Map<string, number> = new Map();
  private weights: Map<string, number> = new Map();

  public selectService(services: ServiceInfo[]): ServiceInfo | null {
    if (services.length === 0) {
      return null;
    }

    let selectedService: ServiceInfo | null = null;
    let minConnections = Infinity;

    for (const service of services) {
      const connections = this.connections.get(service.id) || 0;
      const weight = this.weights.get(service.id) || 1;
      const weightedConnections = connections / weight;

      if (weightedConnections < minConnections) {
        minConnections = weightedConnections;
        selectedService = service;
      }
    }

    if (selectedService) {
      const currentConnections = this.connections.get(selectedService.id) || 0;
      this.connections.set(selectedService.id, currentConnections + 1);
    }

    return selectedService;
  }

  public updateWeights(weights: Record<string, number>): void {
    this.weights.clear();
    for (const [serviceId, weight] of Object.entries(weights)) {
      this.weights.set(serviceId, Math.max(1, weight));
    }
  }

  public releaseConnection(serviceId: string): void {
    const connections = this.connections.get(serviceId) || 0;
    this.connections.set(serviceId, Math.max(0, connections - 1));
  }
}

// ============================================================================
// Service Discovery Client
// ============================================================================

export interface ServiceDiscoveryOptions {
  registry: ServiceRegistry;
  loadBalancer?: LoadBalancer;
  healthCheckInterval?: number;
  retryAttempts?: number;
  retryDelay?: number;
}

export class ServiceDiscoveryClient extends EventEmitter {
  private registry: ServiceRegistry;
  private loadBalancer: LoadBalancer;
  private logger: MCPLogger;
  private healthCheckInterval: number;
  private healthChecks: Map<string, NodeJS.Timeout> = new Map();

  constructor(options: ServiceDiscoveryOptions) {
    super();
    this.registry = options.registry;
    this.loadBalancer = options.loadBalancer || new RoundRobinLoadBalancer();
    this.healthCheckInterval = options.healthCheckInterval || 30000;
    this.logger = createEnhancedLogger('service-discovery-client');
  }

  public async discoverService(serviceType: string): Promise<ServiceInfo | null> {
    const services = await this.registry.discover(serviceType);
    return this.loadBalancer.selectService(services);
  }

  public async discoverServices(serviceType: string): Promise<ServiceInfo[]> {
    return await this.registry.discover(serviceType);
  }

  public watchServices(serviceType: string, callback: (services: ServiceInfo[]) => void): void {
    this.registry.watch(serviceType, callback);
    this.logger.debug(`Started watching services of type: ${serviceType}`);
  }

  public unwatchServices(serviceType: string, callback: (services: ServiceInfo[]) => void): void {
    // this.registry.unwatch(serviceType, callback);
    this.logger.debug(`Stopped watching services of type: ${serviceType}`);
  }

  public async registerService(service: ServiceInfo): Promise<void> {
    await this.registry.register(service);
    this.startHealthCheck(service);
  }

  public async unregisterService(serviceId: string): Promise<void> {
    await this.registry.unregister(serviceId);
    this.stopHealthCheck(serviceId);
  }

  private startHealthCheck(service: ServiceInfo): void {
    if (this.healthChecks.has(service.id)) {
      return; // Already monitoring
    }

    const healthCheck = createHealthCheck(
      `service-${service.id}`,
      async () => {
        try {
          // Perform health check against service endpoint
          const response = await fetch(`${service.endpoint}/health`, {
            method: 'GET',
          } as any);
          return response.ok;
        } catch {
          return false;
        }
      },
      { timeout: 5000 } as any
    );

    const interval = setInterval(async () => {
      try {
        const check = await healthCheck();
        const health = check.status === 'pass' ? HealthStatus.HEALTHY :
                     check.status === 'warn' ? HealthStatus.DEGRADED :
                     HealthStatus.UNHEALTHY;
        
        // await this.registry.updateHealth(service.id, health);
      } catch (error) {
        this.logger.error("Service error:", { serviceId: service.id });
        // await this.registry.updateHealth(service.id, HealthStatus.UNHEALTHY);
      }
    }, this.healthCheckInterval);

    this.healthChecks.set(service.id, interval);
    this.logger.debug(`Started health check for service: ${service.id}`);
  }

  private stopHealthCheck(serviceId: string): void {
    const interval = this.healthChecks.get(serviceId);
    if (interval) {
      clearInterval(interval);
      this.healthChecks.delete(serviceId);
      this.logger.debug(`Stopped health check for service: ${serviceId}`);
    }
  }

  public dispose(): void {
    // Stop all health checks
    for (const [serviceId, interval] of this.healthChecks) {
      clearInterval(interval);
    }
    this.healthChecks.clear();
    this.removeAllListeners();
  }
}

// ============================================================================
// Service Mesh Integration
// ============================================================================

export interface ServiceMeshOptions {
  registry: ServiceRegistry;
  loadBalancer?: LoadBalancer;
  circuitBreakerEnabled?: boolean;
  retryEnabled?: boolean;
  tracingEnabled?: boolean;
}

export class ServiceMesh extends EventEmitter {
  private discovery: ServiceDiscoveryClient;
  private logger: MCPLogger;
  private circuitBreakers: Map<string, any> = new Map();

  constructor(options: ServiceMeshOptions) {
    super();
    this.discovery = new ServiceDiscoveryClient({
      registry: options.registry,
      loadBalancer: options.loadBalancer,
    });
    this.logger = createEnhancedLogger('service-mesh');
  }

  public async callService(serviceType: string, method: string, params: any): Promise<any> {
    const service = await this.discovery.discoverService(serviceType);
    if (!service) {
      throw new Error(`No healthy service found for type: ${serviceType}`);
    }

    this.logger.info(`Calling service: ${service.name} (${service.id})`, { method, serviceType });

    try {
      // Make the actual service call
      const response = await this.makeServiceCall(service, method, params);
      this.emit('service_call_success', { service, method, params });
      return response;
    } catch (error) {
      this.logger.error("Service error:", { service: service.id, method, serviceType });
      this.emit('service_call_failure', { service, method, params, error });
      throw error;
    }
  }

  private async makeServiceCall(service: ServiceInfo, method: string, params: any): Promise<any> {
    // This is a simplified implementation
    // In a real implementation, you would use the appropriate transport protocol
    const response = await fetch(`${service.endpoint}/rpc`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method,
        params,
        id: Date.now(),
      }),
    });

    if (!response.ok) {
      throw new Error(`Service call failed: ${response.statusText}`);
    }

    const result = await response.json();
    if ((result as any).error) {
      throw new Error(`Service returned error: ${(result as any).error.message}`);
    }

    return (result as any).result;
  }

  public dispose(): void {
    this.discovery.dispose();
    this.removeAllListeners();
  }
}

// ============================================================================
// Factory Functions
// ============================================================================

export function createServiceRegistry(): ServiceRegistry {
  return new InMemoryServiceRegistry();
}

export function createLoadBalancer(type: 'round-robin' | 'weighted' | 'least-connections'): LoadBalancer {
  switch (type) {
    case 'round-robin':
      return new RoundRobinLoadBalancer();
    case 'weighted':
      return new WeightedRoundRobinLoadBalancer();
    case 'least-connections':
      return new LeastConnectionsLoadBalancer();
    default:
      throw new Error(`Unknown load balancer type: ${type}`);
  }
}

export function createServiceDiscoveryClient(options: ServiceDiscoveryOptions): ServiceDiscoveryClient {
  return new ServiceDiscoveryClient(options);
}

export function createServiceMesh(options: ServiceMeshOptions): ServiceMesh {
  return new ServiceMesh(options);
}