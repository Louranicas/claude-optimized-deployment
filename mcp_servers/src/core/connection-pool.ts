/**
 * Connection Pool Manager for MCP Servers
 * Optimized for high-performance database and HTTP connections
 */

import { EventEmitter } from 'events';
import { Pool as PgPool, PoolClient, PoolConfig } from 'pg';
import mysql from 'mysql2/promise';
import { Agent as HttpAgent } from 'http';
import { Agent as HttpsAgent } from 'https';
import { Logger } from 'pino';

export interface ConnectionPoolConfig {
  database: {
    postgres?: {
      host: string;
      port: number;
      database: string;
      user: string;
      password: string;
      ssl?: boolean;
      poolSize: number;
      maxPoolSize: number;
      idleTimeoutMillis: number;
      connectionTimeoutMillis: number;
    };
    mysql?: {
      host: string;
      port: number;
      database: string;
      user: string;
      password: string;
      ssl?: boolean;
      connectionLimit: number;
      queueLimit: number;
      acquireTimeout: number;
      timeout: number;
    };
  };
  http: {
    maxSockets: number;
    maxFreeSockets: number;
    timeout: number;
    keepAlive: boolean;
    keepAliveMsecs: number;
    freeSocketTimeout: number;
    socketActiveTTL: number;
  };
  redis?: {
    host: string;
    port: number;
    password?: string;
    db: number;
    maxRetriesPerRequest: number;
    retryDelayOnFailover: number;
    enableReadyCheck: boolean;
    keepAlive: number;
    family: number;
    connectTimeout: number;
    lazyConnect: boolean;
  };
}

export interface PoolMetrics {
  totalConnections: number;
  activeConnections: number;
  idleConnections: number;
  waitingCount: number;
  errors: number;
  acquisitionTime: number;
  utilizationRate: number;
}

export interface DatabaseConnection {
  query<T = any>(sql: string, params?: any[]): Promise<T>;
  release(): void;
  close(): Promise<void>;
}

export class PostgreSQLPool extends EventEmitter {
  private pool: PgPool;
  private logger: Logger;
  private metrics: PoolMetrics;

  constructor(config: NonNullable<ConnectionPoolConfig['database']['postgres']>, logger: Logger) {
    super();
    this.logger = logger;
    this.metrics = this.initializeMetrics();

    const poolConfig: PoolConfig = {
      host: config.host,
      port: config.port,
      database: config.database,
      user: config.user,
      password: config.password,
      ssl: config.ssl,
      min: Math.floor(config.poolSize * 0.1), // 10% minimum connections
      max: config.maxPoolSize,
      idleTimeoutMillis: config.idleTimeoutMillis,
      connectionTimeoutMillis: config.connectionTimeoutMillis,
      allowExitOnIdle: true,
    };

    this.pool = new PgPool(poolConfig);
    this.setupEventHandlers();
    this.startMetricsCollection();
  }

  private initializeMetrics(): PoolMetrics {
    return {
      totalConnections: 0,
      activeConnections: 0,
      idleConnections: 0,
      waitingCount: 0,
      errors: 0,
      acquisitionTime: 0,
      utilizationRate: 0,
    };
  }

  private setupEventHandlers(): void {
    this.pool.on('connect', (client) => {
      this.metrics.totalConnections++;
      this.logger.info('New PostgreSQL client connected');
    });

    this.pool.on('acquire', (client) => {
      this.metrics.activeConnections++;
      this.emit('acquire', client);
    });

    this.pool.on('release', (err, client) => {
      this.metrics.activeConnections--;
      if (err) {
        this.metrics.errors++;
        this.logger.error({ error: err }, 'Error releasing PostgreSQL client');
      }
      this.emit('release', err, client);
    });

    this.pool.on('error', (err, client) => {
      this.metrics.errors++;
      this.logger.error({ error: err }, 'PostgreSQL pool error');
      this.emit('error', err, client);
    });

    this.pool.on('remove', (client) => {
      this.metrics.totalConnections--;
      this.logger.info('PostgreSQL client removed from pool');
    });
  }

  private startMetricsCollection(): void {
    setInterval(() => {
      this.updateMetrics();
    }, 5000); // Update metrics every 5 seconds
  }

  private updateMetrics(): void {
    this.metrics.idleConnections = this.pool.idleCount;
    this.metrics.waitingCount = this.pool.waitingCount;
    this.metrics.utilizationRate = (this.metrics.activeConnections / this.pool.totalCount) * 100 || 0;
    this.emit('metrics', this.metrics);
  }

  async getConnection(): Promise<PoolClient> {
    const startTime = Date.now();
    try {
      const client = await this.pool.connect();
      this.metrics.acquisitionTime = Date.now() - startTime;
      return client;
    } catch (error) {
      this.metrics.errors++;
      this.logger.error({ error }, 'Failed to acquire PostgreSQL connection');
      throw error;
    }
  }

  async query<T = any>(sql: string, params?: any[]): Promise<T> {
    const client = await this.getConnection();
    try {
      const result = await client.query(sql, params);
      return result.rows as T;
    } finally {
      client.release();
    }
  }

  async transaction<T>(callback: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.getConnection();
    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  getMetrics(): PoolMetrics {
    return { ...this.metrics };
  }

  async close(): Promise<void> {
    await this.pool.end();
    this.logger.info('PostgreSQL pool closed');
  }
}

export class MySQLPool extends EventEmitter {
  private pool: mysql.Pool;
  private logger: Logger;
  private metrics: PoolMetrics;

  constructor(config: NonNullable<ConnectionPoolConfig['database']['mysql']>, logger: Logger) {
    super();
    this.logger = logger;
    this.metrics = this.initializeMetrics();

    this.pool = mysql.createPool({
      host: config.host,
      port: config.port,
      database: config.database,
      user: config.user,
      password: config.password,
      ssl: config.ssl ? { rejectUnauthorized: false } : undefined,
      connectionLimit: config.connectionLimit,
      queueLimit: config.queueLimit,
      reconnect: true,
      idleTimeout: 300000, // 5 minutes
      enableKeepAlive: true,
      keepAliveInitialDelay: 0,
    } as any);

    this.setupEventHandlers();
    this.startMetricsCollection();
  }

  private initializeMetrics(): PoolMetrics {
    return {
      totalConnections: 0,
      activeConnections: 0,
      idleConnections: 0,
      waitingCount: 0,
      errors: 0,
      acquisitionTime: 0,
      utilizationRate: 0,
    };
  }

  private setupEventHandlers(): void {
    this.pool.on('connection', (connection) => {
      this.metrics.totalConnections++;
      this.logger.info('New MySQL connection established');
      
      connection.on('error', (err) => {
        this.metrics.errors++;
        this.logger.error({ error: err }, 'MySQL connection error');
      });
    });

    this.pool.on('acquire', (connection) => {
      this.metrics.activeConnections++;
      this.emit('acquire', connection);
    });

    this.pool.on('release', (connection) => {
      this.metrics.activeConnections--;
      this.emit('release', connection);
    });

    this.pool.on('enqueue', () => {
      this.metrics.waitingCount++;
    });
  }

  private startMetricsCollection(): void {
    setInterval(() => {
      this.updateMetrics();
    }, 5000);
  }

  private updateMetrics(): void {
    // MySQL pool doesn't expose idle count directly, calculate it
    this.metrics.idleConnections = this.metrics.totalConnections - this.metrics.activeConnections;
    this.metrics.utilizationRate = (this.metrics.activeConnections / this.metrics.totalConnections) * 100 || 0;
    this.emit('metrics', this.metrics);
  }

  async getConnection(): Promise<mysql.PoolConnection> {
    const startTime = Date.now();
    try {
      const connection = await this.pool.getConnection();
      this.metrics.acquisitionTime = Date.now() - startTime;
      return connection;
    } catch (error) {
      this.metrics.errors++;
      this.logger.error({ error }, 'Failed to acquire MySQL connection');
      throw error;
    }
  }

  async query<T = any>(sql: string, params?: any[]): Promise<T> {
    const connection = await this.getConnection();
    try {
      const [rows] = await connection.execute(sql, params);
      return rows as T;
    } finally {
      connection.release();
    }
  }

  async transaction<T>(callback: (connection: mysql.PoolConnection) => Promise<T>): Promise<T> {
    const connection = await this.getConnection();
    try {
      await connection.beginTransaction();
      const result = await callback(connection);
      await connection.commit();
      return result;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  getMetrics(): PoolMetrics {
    return { ...this.metrics };
  }

  async close(): Promise<void> {
    await this.pool.end();
    this.logger.info('MySQL pool closed');
  }
}

export class HTTPConnectionPool extends EventEmitter {
  private httpAgent: HttpAgent;
  private httpsAgent: HttpsAgent;
  private logger: Logger;
  private metrics: PoolMetrics;

  constructor(config: ConnectionPoolConfig['http'], logger: Logger) {
    super();
    this.logger = logger;
    this.metrics = this.initializeMetrics();

    // Create HTTP agent with optimized settings
    this.httpAgent = new HttpAgent({
      maxSockets: config.maxSockets,
      maxFreeSockets: config.maxFreeSockets,
      timeout: config.timeout,
      keepAlive: config.keepAlive,
      keepAliveMsecs: config.keepAliveMsecs,
      scheduling: 'fifo', // First-in-first-out scheduling
    } as any);

    // Create HTTPS agent with optimized settings
    this.httpsAgent = new HttpsAgent({
      maxSockets: config.maxSockets,
      maxFreeSockets: config.maxFreeSockets,
      timeout: config.timeout,
      keepAlive: config.keepAlive,
      keepAliveMsecs: config.keepAliveMsecs,
      scheduling: 'fifo',
    } as any);

    this.setupEventHandlers();
    this.startMetricsCollection();
  }

  private initializeMetrics(): PoolMetrics {
    return {
      totalConnections: 0,
      activeConnections: 0,
      idleConnections: 0,
      waitingCount: 0,
      errors: 0,
      acquisitionTime: 0,
      utilizationRate: 0,
    };
  }

  private setupEventHandlers(): void {
    // Monitor HTTP agent sockets
    const originalCreateConnection = (this.httpAgent as any).createConnection?.bind(this.httpAgent);
    (this.httpAgent as any).createConnection = (options: any, callback: any) => {
      this.metrics.totalConnections++;
      this.metrics.activeConnections++;
      this.logger.debug('HTTP connection created');
      
      const socket = originalCreateConnection(options, callback);
      
      socket.on('close', () => {
        this.metrics.totalConnections--;
        this.metrics.activeConnections--;
        this.logger.debug('HTTP connection closed');
      });

      socket.on("error", (error: any) => {
        this.metrics.errors++;
        this.logger.error({ error }, 'HTTP socket error');
      });

      return socket;
    };

    // Monitor HTTPS agent sockets
    const originalHttpsCreateConnection = (this.httpsAgent as any).createConnection?.bind(this.httpsAgent);
    (this.httpsAgent as any).createConnection = (options: any, callback: any) => {
      this.metrics.totalConnections++;
      this.metrics.activeConnections++;
      this.logger.debug('HTTPS connection created');
      
      const socket = originalHttpsCreateConnection(options, callback);
      
      socket.on('close', () => {
        this.metrics.totalConnections--;
        this.metrics.activeConnections--;
        this.logger.debug('HTTPS connection closed');
      });

      socket.on("error", (error: any) => {
        this.metrics.errors++;
        this.logger.error({ error }, 'HTTPS socket error');
      });

      return socket;
    };
  }

  private startMetricsCollection(): void {
    setInterval(() => {
      this.updateMetrics();
    }, 5000);
  }

  private updateMetrics(): void {
    // Calculate idle connections from free sockets
    const httpFreeSockets = Object.values(this.httpAgent.freeSockets).reduce((total, sockets) => total + sockets.length, 0);
    const httpsFreeSockets = Object.values(this.httpsAgent.freeSockets).reduce((total, sockets) => total + sockets.length, 0);
    
    this.metrics.idleConnections = httpFreeSockets + httpsFreeSockets;
    this.metrics.utilizationRate = this.metrics.totalConnections > 0 
      ? ((this.metrics.totalConnections - this.metrics.idleConnections) / this.metrics.totalConnections) * 100 
      : 0;
    
    this.emit('metrics', this.metrics);
  }

  getHttpAgent(): HttpAgent {
    return this.httpAgent;
  }

  getHttpsAgent(): HttpsAgent {
    return this.httpsAgent;
  }

  getMetrics(): PoolMetrics {
    return { ...this.metrics };
  }

  destroy(): void {
    this.httpAgent.destroy();
    this.httpsAgent.destroy();
    this.logger.info('HTTP connection pools destroyed');
  }
}

export class ConnectionPoolManager extends EventEmitter {
  private pgPool?: PostgreSQLPool;
  private mysqlPool?: MySQLPool;
  private httpPool: HTTPConnectionPool;
  private logger: Logger;
  private config: ConnectionPoolConfig;

  constructor(config: ConnectionPoolConfig, logger: Logger) {
    super();
    this.config = config;
    this.logger = logger;

    // Initialize database pools if configured
    if (config.database.postgres) {
      this.pgPool = new PostgreSQLPool(config.database.postgres, logger);
      this.pgPool.on('metrics', (metrics) => this.emit('db-metrics', { type: 'postgres', metrics }));
      this.pgPool.on('error', (error) => this.emit('error', { type: 'postgres', error }));
    }

    if (config.database.mysql) {
      this.mysqlPool = new MySQLPool(config.database.mysql, logger);
      this.mysqlPool.on('metrics', (metrics) => this.emit('db-metrics', { type: 'mysql', metrics }));
      this.mysqlPool.on('error', (error) => this.emit('error', { type: 'mysql', error }));
    }

    // Initialize HTTP pool
    this.httpPool = new HTTPConnectionPool(config.http, logger);
    this.httpPool.on('metrics', (metrics) => this.emit('http-metrics', metrics));
    this.httpPool.on('error', (error) => this.emit('error', { type: 'http', error }));

    this.logger.info('Connection pool manager initialized');
  }

  // Database operations
  async queryPostgres<T = any>(sql: string, params?: any[]): Promise<T> {
    if (!this.pgPool) {
      throw new Error('PostgreSQL pool not configured');
    }
    return this.pgPool.query<T>(sql, params);
  }

  async queryMySQL<T = any>(sql: string, params?: any[]): Promise<T> {
    if (!this.mysqlPool) {
      throw new Error('MySQL pool not configured');
    }
    return this.mysqlPool.query<T>(sql, params);
  }

  async transactionPostgres<T>(callback: (client: any) => Promise<T>): Promise<T> {
    if (!this.pgPool) {
      throw new Error('PostgreSQL pool not configured');
    }
    return this.pgPool.transaction(callback);
  }

  async transactionMySQL<T>(callback: (connection: any) => Promise<T>): Promise<T> {
    if (!this.mysqlPool) {
      throw new Error('MySQL pool not configured');
    }
    return this.mysqlPool.transaction(callback);
  }

  // HTTP operations
  getHttpAgent(): HttpAgent {
    return this.httpPool.getHttpAgent();
  }

  getHttpsAgent(): HttpsAgent {
    return this.httpPool.getHttpsAgent();
  }

  // Metrics collection
  getAllMetrics(): { [key: string]: PoolMetrics } {
    const metrics: { [key: string]: PoolMetrics } = {};

    if (this.pgPool) {
      metrics.postgres = this.pgPool.getMetrics();
    }

    if (this.mysqlPool) {
      metrics.mysql = this.mysqlPool.getMetrics();
    }

    metrics.http = this.httpPool.getMetrics();

    return metrics;
  }

  // Health checks
  async healthCheck(): Promise<{ [key: string]: boolean }> {
    const health: { [key: string]: boolean } = {};

    if (this.pgPool) {
      try {
        await this.pgPool.query('SELECT 1');
        health.postgres = true;
      } catch (error) {
        health.postgres = false;
        this.logger.error({ error }, 'PostgreSQL health check failed');
      }
    }

    if (this.mysqlPool) {
      try {
        await this.mysqlPool.query('SELECT 1');
        health.mysql = true;
      } catch (error) {
        health.mysql = false;
        this.logger.error({ error }, 'MySQL health check failed');
      }
    }

    health.http = true; // HTTP pools are always considered healthy if created

    return health;
  }

  // Cleanup
  async close(): Promise<void> {
    const closePromises: Promise<void>[] = [];

    if (this.pgPool) {
      closePromises.push(this.pgPool.close());
    }

    if (this.mysqlPool) {
      closePromises.push(this.mysqlPool.close());
    }

    this.httpPool.destroy();

    await Promise.all(closePromises);
    this.logger.info('All connection pools closed');
  }
}