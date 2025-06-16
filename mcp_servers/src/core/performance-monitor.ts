/**
 * Performance Monitor for MCP Servers
 * Real-time monitoring, alerting, and dashboard capabilities
 */

import { EventEmitter } from 'events';
import { Logger } from 'pino';
import { PerformanceMetrics } from './performance-optimizer';
import { PoolMetrics } from './connection-pool';
import * as prometheus from 'prom-client';
import WebSocket from 'ws';
import express from 'express';
import http from 'http';

export interface MonitoringConfig {
  dashboard: {
    enabled: boolean;
    port: number;
    host: string;
    updateInterval: number;
  };
  prometheus: {
    enabled: boolean;
    port: number;
    endpoint: string;
  };
  alerts: {
    enabled: boolean;
    webhookUrl?: string;
    emailConfig?: {
      smtp: {
        host: string;
        port: number;
        secure: boolean;
        auth: {
          user: string;
          pass: string;
        };
      };
      from: string;
      to: string[];
    };
    thresholds: {
      cpuUsage: number;
      memoryUsage: number;
      responseTime: number;
      errorRate: number;
      connectionPoolUtilization: number;
    };
  };
  retention: {
    metricsRetentionHours: number;
    samplingInterval: number;
  };
}

export interface Alert {
  id: string;
  type: 'cpu' | 'memory' | 'response_time' | 'error_rate' | 'connection_pool' | 'custom';
  severity: 'info' | 'warning' | 'critical';
  message: string;
  timestamp: Date;
  value: number;
  threshold: number;
  serverId?: string;
  resolved: boolean;
  resolvedAt?: Date;
}

export interface MetricsSnapshot {
  timestamp: Date;
  performance: PerformanceMetrics;
  connectionPools: { [poolName: string]: PoolMetrics };
  alerts: Alert[];
  uptime: number;
}

export class PerformanceMonitor extends EventEmitter {
  private config: MonitoringConfig;
  private logger: Logger;
  private metrics: MetricsSnapshot[] = [];
  private activeAlerts: Map<string, Alert> = new Map();
  private prometheusMetrics: { [key: string]: prometheus.Metric } = {};
  private dashboardServer?: http.Server;
  private wsServer?: WebSocket.Server;
  private clients: Set<WebSocket> = new Set();
  private metricsInterval?: NodeJS.Timeout;
  private cleanupInterval?: NodeJS.Timeout;
  private startTime = Date.now();

  constructor(config: MonitoringConfig, logger: Logger) {
    super();
    this.config = config;
    this.logger = logger;

    this.initializePrometheusMetrics();
    this.startMetricsCollection();
    this.startMetricsCleanup();

    if (config.dashboard.enabled) {
      this.startDashboard();
    }

    if (config.prometheus.enabled) {
      this.startPrometheusServer();
    }
  }

  private initializePrometheusMetrics(): void {
    const register = prometheus.register;

    // Clear existing metrics to avoid conflicts
    register.clear();

    // CPU Metrics
    (this.prometheusMetrics as any).cpuUsage = new prometheus.Gauge({
      name: 'mcp_server_cpu_usage_percent',
      help: 'CPU usage percentage',
      labelNames: ['server_id']
    });

    (this.prometheusMetrics as any).cpuLoadAverage = new prometheus.Gauge({
      name: 'mcp_server_cpu_load_average',
      help: 'CPU load average',
      labelNames: ['server_id', 'period']
    });

    // Memory Metrics
    (this.prometheusMetrics as any).memoryUsage = new prometheus.Gauge({
      name: 'mcp_server_memory_usage_bytes',
      help: 'Memory usage in bytes',
      labelNames: ['server_id', 'type']
    });

    (this.prometheusMetrics as any).memoryPercentage = new prometheus.Gauge({
      name: 'mcp_server_memory_usage_percent',
      help: 'Memory usage percentage',
      labelNames: ['server_id']
    });

    // Request Metrics
    (this.prometheusMetrics as any).requestsTotal = new prometheus.Counter({
      name: 'mcp_server_requests_total',
      help: 'Total number of requests',
      labelNames: ['server_id', 'method', 'status']
    });

    (this.prometheusMetrics as any).requestDuration = new prometheus.Histogram({
      name: 'mcp_server_request_duration_seconds',
      help: 'Request duration in seconds',
      labelNames: ['server_id', 'method'],
      buckets: [0.1, 0.25, 0.5, 1, 2.5, 5, 10]
    });

    (this.prometheusMetrics as any).errorRate = new prometheus.Gauge({
      name: 'mcp_server_error_rate_percent',
      help: 'Error rate percentage',
      labelNames: ['server_id']
    });

    // Connection Pool Metrics
    (this.prometheusMetrics as any).connectionPoolActive = new prometheus.Gauge({
      name: 'mcp_server_connection_pool_active',
      help: 'Active connections in pool',
      labelNames: ['server_id', 'pool_type']
    });

    (this.prometheusMetrics as any).connectionPoolIdle = new prometheus.Gauge({
      name: 'mcp_server_connection_pool_idle',
      help: 'Idle connections in pool',
      labelNames: ['server_id', 'pool_type']
    });

    (this.prometheusMetrics as any).connectionPoolUtilization = new prometheus.Gauge({
      name: 'mcp_server_connection_pool_utilization_percent',
      help: 'Connection pool utilization percentage',
      labelNames: ['server_id', 'pool_type']
    });

    // Cache Metrics
    (this.prometheusMetrics as any).cacheHitRate = new prometheus.Gauge({
      name: 'mcp_server_cache_hit_rate_percent',
      help: 'Cache hit rate percentage',
      labelNames: ['server_id', 'cache_type']
    });

    (this.prometheusMetrics as any).cacheSize = new prometheus.Gauge({
      name: 'mcp_server_cache_size',
      help: 'Cache size',
      labelNames: ['server_id', 'cache_type']
    });

    // Custom Application Metrics
    (this.prometheusMetrics as any).uptime = new prometheus.Gauge({
      name: 'mcp_server_uptime_seconds',
      help: 'Server uptime in seconds',
      labelNames: ['server_id']
    });

    (this.prometheusMetrics as any).alertsActive = new prometheus.Gauge({
      name: 'mcp_server_alerts_active',
      help: 'Number of active alerts',
      labelNames: ['server_id', 'severity']
    });
  }

  private startMetricsCollection(): void {
    this.metricsInterval = setInterval(() => {
      this.collectMetrics();
    }, this.config.retention.samplingInterval);
  }

  private startMetricsCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanupOldMetrics();
    }, 60000); // Clean up every minute
  }

  private collectMetrics(): void {
    // This will be called by the performance optimizer
    // For now, we just emit an event to request metrics
    this.emit('collect-metrics');
  }

  private cleanupOldMetrics(): void {
    const cutoffTime = new Date(Date.now() - (this.config.retention.metricsRetentionHours * 60 * 60 * 1000));
    
    const initialLength = this.metrics.length;
    this.metrics = this.metrics.filter(metric => metric.timestamp > cutoffTime);
    
    const removedCount = initialLength - this.metrics.length;
    if (removedCount > 0) {
      this.logger.debug({ removedCount }, 'Cleaned up old metrics');
    }
  }

  // Metrics recording
  recordMetrics(
    serverId: string,
    performance: PerformanceMetrics,
    connectionPools: { [poolName: string]: PoolMetrics } = {}
  ): void {
    const snapshot: MetricsSnapshot = {
      timestamp: new Date(),
      performance,
      connectionPools,
      alerts: Array.from(this.activeAlerts.values()),
      uptime: Math.floor((Date.now() - this.startTime) / 1000)
    };

    this.metrics.push(snapshot);
    this.updatePrometheusMetrics(serverId, snapshot);
    this.checkAlerts(serverId, snapshot);
    this.broadcastToClients(snapshot);

    this.emit('metrics-recorded', snapshot);
  }

  private updatePrometheusMetrics(serverId: string, snapshot: MetricsSnapshot): void {
    const { performance, connectionPools, uptime } = snapshot;

    // CPU Metrics
    if (performance.cpu) {
      (this.prometheusMetrics as any).cpuUsage?.set?.({ server_id: serverId }, performance.cpu.usage);
      performance.cpu.loadAverage.forEach((load, index) => {
        const period = ['1m', '5m', '15m'][index];
        (this.prometheusMetrics as any).cpuLoadAverage?.set?.({ server_id: serverId, period }, load);
      });
    }

    // Memory Metrics
    if (performance.memory) {
      (this.prometheusMetrics as any).memoryUsage?.set?.({ server_id: serverId, type: 'used' }, performance.memory.used);
      (this.prometheusMetrics as any).memoryUsage?.set?.({ server_id: serverId, type: 'total' }, performance.memory.total);
      (this.prometheusMetrics as any).memoryUsage?.set?.({ server_id: serverId, type: 'heap_used' }, performance.memory.heapUsed);
      (this.prometheusMetrics as any).memoryUsage?.set?.({ server_id: serverId, type: 'heap_total' }, performance.memory.heapTotal);
      (this.prometheusMetrics as any).memoryPercentage?.set?.({ server_id: serverId }, performance.memory.percentage);
    }

    // Request Metrics
    if (performance.requests) {
      (this.prometheusMetrics as any).errorRate?.set?.({ server_id: serverId }, performance.requests.errorRate);
    }

    // Connection Pool Metrics
    Object.entries(connectionPools).forEach(([poolName, poolMetrics]) => {
      (this.prometheusMetrics as any).connectionPoolActive?.set?.({ server_id: serverId, pool_type: poolName }, poolMetrics.activeConnections);
      (this.prometheusMetrics as any).connectionPoolIdle?.set?.({ server_id: serverId, pool_type: poolName }, poolMetrics.idleConnections);
      (this.prometheusMetrics as any).connectionPoolUtilization?.set?.({ server_id: serverId, pool_type: poolName }, poolMetrics.utilizationRate);
    });

    // Cache Metrics
    if (performance.cache) {
      (this.prometheusMetrics as any).cacheHitRate?.set?.({ server_id: serverId, cache_type: 'lru' }, performance.cache.hitRate);
      (this.prometheusMetrics as any).cacheSize?.set?.({ server_id: serverId, cache_type: 'lru' }, performance.cache.size);
    }

    // Uptime
    (this.prometheusMetrics as any).uptime?.set?.({ server_id: serverId }, uptime);

    // Active Alerts
    const alertsByServerity = this.getAlertCountBySeverity();
    Object.entries(alertsByServerity).forEach(([severity, count]) => {
      (this.prometheusMetrics as any).alertsActive?.set?.({ server_id: serverId, severity }, count);
    });
  }

  private checkAlerts(serverId: string, snapshot: MetricsSnapshot): void {
    const { thresholds } = this.config.alerts;
    const { performance, connectionPools } = snapshot;

    // CPU Alert
    if (performance.cpu && performance.cpu.usage > thresholds.cpuUsage) {
      this.triggerAlert('cpu', 'warning', `CPU usage ${performance.cpu.usage.toFixed(1)}% exceeds threshold ${thresholds.cpuUsage}%`, performance.cpu.usage, thresholds.cpuUsage, serverId);
    }

    // Memory Alert
    if (performance.memory && performance.memory.percentage > thresholds.memoryUsage) {
      this.triggerAlert('memory', 'warning', `Memory usage ${performance.memory.percentage.toFixed(1)}% exceeds threshold ${thresholds.memoryUsage}%`, performance.memory.percentage, thresholds.memoryUsage, serverId);
    }

    // Response Time Alert
    if (performance.requests && performance.requests.averageResponseTime > thresholds.responseTime) {
      this.triggerAlert('response_time', 'warning', `Average response time ${performance.requests.averageResponseTime.toFixed(1)}ms exceeds threshold ${thresholds.responseTime}ms`, performance.requests.averageResponseTime, thresholds.responseTime, serverId);
    }

    // Error Rate Alert
    if (performance.requests && performance.requests.errorRate > thresholds.errorRate) {
      this.triggerAlert('error_rate', 'critical', `Error rate ${performance.requests.errorRate.toFixed(1)}% exceeds threshold ${thresholds.errorRate}%`, performance.requests.errorRate, thresholds.errorRate, serverId);
    }

    // Connection Pool Alerts
    Object.entries(connectionPools).forEach(([poolName, poolMetrics]) => {
      if (poolMetrics.utilizationRate > thresholds.connectionPoolUtilization) {
        this.triggerAlert('connection_pool', 'warning', `${poolName} pool utilization ${poolMetrics.utilizationRate.toFixed(1)}% exceeds threshold ${thresholds.connectionPoolUtilization}%`, poolMetrics.utilizationRate, thresholds.connectionPoolUtilization, serverId);
      }
    });
  }

  private triggerAlert(type: Alert['type'], severity: Alert['severity'], message: string, value: number, threshold: number, serverId?: string): void {
    const alertId = `${type}_${serverId || 'global'}_${Date.now()}`;
    
    // Check if similar alert already exists
    const existingAlert = Array.from(this.activeAlerts.values()).find(alert => 
      alert.type === type && alert.serverId === serverId && !alert.resolved
    );

    if (existingAlert) {
      // Update existing alert
      existingAlert.message = message;
      existingAlert.value = value;
      existingAlert.timestamp = new Date();
    } else {
      // Create new alert
      const alert: Alert = {
        id: alertId,
        type,
        severity,
        message,
        timestamp: new Date(),
        value,
        threshold,
        serverId,
        resolved: false
      };

      this.activeAlerts?.set?.(alertId, alert);
      this.logger.warn({ alert }, 'Alert triggered');
      this.emit('alert', alert);

      if (this.config.alerts.enabled) {
        this.sendAlertNotification(alert);
      }
    }
  }

  private async sendAlertNotification(alert: Alert): Promise<void> {
    try {
      // Webhook notification
      if (this.config.alerts.webhookUrl) {
        const response = await fetch(this.config.alerts.webhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(alert)
        });

        if (!response.ok) {
          this.logger.error({ status: response.status }, 'Failed to send webhook alert');
        }
      }

      // Email notification (implement with nodemailer if needed)
      if (this.config.alerts.emailConfig) {
        // TODO: Implement email notifications
        this.logger.info('Email notification would be sent here');
      }
    } catch (error) {
      this.logger.error({ error }, 'Failed to send alert notification');
    }
  }

  resolveAlert(alertId: string): void {
    const alert = this.activeAlerts.get(alertId);
    if (alert && !alert.resolved) {
      alert.resolved = true;
      alert.resolvedAt = new Date();
      this.logger.info({ alertId }, 'Alert resolved');
      this.emit('alert-resolved', alert);
    }
  }

  private getAlertCountBySeverity(): { [severity: string]: number } {
    const counts = { info: 0, warning: 0, critical: 0 };
    
    for (const alert of this.activeAlerts.values()) {
      if (!alert.resolved) {
        counts[alert.severity]++;
      }
    }

    return counts;
  }

  // Dashboard
  private startDashboard(): void {
    const app = express();
    
    // Serve static files
    app.use(express.static(__dirname + '/dashboard'));
    
    // API endpoints
    app.get('/api/metrics/current', (req, res) => {
      const latest = this.metrics[this.metrics.length - 1];
      res.json(latest || {});
    });

    app.get('/api/metrics/history', (req, res) => {
      const hours = parseInt(req.query.hours as string) || 1;
      const since = new Date(Date.now() - (hours * 60 * 60 * 1000));
      const filtered = this.metrics.filter(m => m.timestamp > since);
      res.json(filtered);
    });

    app.get('/api/alerts', (req, res) => {
      const alerts = Array.from(this.activeAlerts.values())
        .filter(a => !a.resolved || (a.resolvedAt && a.resolvedAt > new Date(Date.now() - 24 * 60 * 60 * 1000)));
      res.json(alerts);
    });

    app.post('/api/alerts/:id/resolve', (req, res) => {
      this.resolveAlert(req.params.id);
      res.json({ success: true });
    });

    // Create HTTP server
    this.dashboardServer = http.createServer(app);
    
    // WebSocket server for real-time updates
    this.wsServer = new WebSocket.Server({ server: this.dashboardServer });
    this.wsServer.on('connection', (ws) => {
      this.clients.add(ws);
      
      ws.on('close', () => {
        this.clients.delete(ws);
      });

      ws.on('error', (error) => {
        this.logger.error({ error }, 'WebSocket error');
        this.clients.delete(ws);
      });

      // Send current metrics to new client
      const latest = this.metrics[this.metrics.length - 1];
      if (latest) {
        ws.send(JSON.stringify({ type: 'metrics', data: latest }));
      }
    });

    this.dashboardServer.listen(this.config.dashboard.port, this.config.dashboard.host, () => {
      this.logger.info({ 
        host: this.config.dashboard.host, 
        port: this.config.dashboard.port 
      }, 'Performance dashboard started');
    });
  }

  private broadcastToClients(data: any): void {
    const message = JSON.stringify({ type: 'metrics', data });
    
    this.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        try {
          client.send(message);
        } catch (error) {
          this.logger.error({ error }, 'Failed to send WebSocket message');
          this.clients.delete(client);
        }
      }
    });
  }

  // Prometheus server
  private startPrometheusServer(): void {
    const app = express();
    
    app.get(this.config.prometheus.endpoint, async (req, res) => {
      try {
        res?.set?.('Content-Type', prometheus.register.contentType);
        res.end(await prometheus.register.metrics());
      } catch (error) {
        res.status(500).end(error);
      }
    });

    app.listen(this.config.prometheus.port, () => {
      this.logger.info({ 
        port: this.config.prometheus.port, 
        endpoint: this.config.prometheus.endpoint 
      }, 'Prometheus metrics server started');
    });
  }

  // Public API
  getMetrics(hours: number = 1): MetricsSnapshot[] {
    const since = new Date(Date.now() - (hours * 60 * 60 * 1000));
    return this.metrics.filter(m => m.timestamp > since);
  }

  getCurrentMetrics(): MetricsSnapshot | null {
    return this.metrics[this.metrics.length - 1] || null;
  }

  getAlerts(includeResolved: boolean = false): Alert[] {
    return Array.from(this.activeAlerts.values())
      .filter(alert => includeResolved || !alert.resolved);
  }

  getActiveAlertCount(): number {
    return Array.from(this.activeAlerts.values())
      .filter(alert => !alert.resolved).length;
  }

  // Record custom metrics
  recordCustomMetric(name: string, value: number, labels: { [key: string]: string } = {}): void {
    if (!this.prometheusMetrics[name]) {
      this.prometheusMetrics[name] = new prometheus.Gauge({
        name: `mcp_server_custom_${name}`,
        help: `Custom metric: ${name}`,
        labelNames: Object.keys(labels)
      });
    }

    (this.prometheusMetrics[name] as prometheus.Gauge)?.set?.(labels, value);
  }

  // Cleanup
  async cleanup(): Promise<void> {
    if (this.metricsInterval) {
      clearInterval(this.metricsInterval);
    }

    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }

    if (this.dashboardServer) {
      this.dashboardServer.close();
    }

    if (this.wsServer) {
      this.wsServer.close();
    }

    this.clients.clear();
    this.metrics = [];
    this.activeAlerts.clear();

    this.logger.info('Performance monitor cleaned up');
  }
}

// Factory function for easy setup
export function createPerformanceMonitor(
  config: Partial<MonitoringConfig> = {},
  logger: Logger
): PerformanceMonitor {
  const defaultConfig: MonitoringConfig = {
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
  };

  const finalConfig = { ...defaultConfig, ...config };
  return new PerformanceMonitor(finalConfig, logger);
}