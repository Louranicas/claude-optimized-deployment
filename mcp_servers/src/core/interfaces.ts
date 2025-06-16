/**
 * Common Interface Definitions for MCP Server Architecture
 * 
 * These interfaces provide cross-language compatibility and standardization
 * across TypeScript, Python, and Rust implementations.
 */

// ============================================================================
// Core Server Interfaces
// ============================================================================

export interface MCPServerIdentity {
  name: string;
  version: string;
  description: string;
  author?: string;
  license?: string;
  repository?: string;
}

export interface ServerCapabilities {
  tools?: boolean;
  resources?: boolean;
  prompts?: boolean;
  roots?: boolean;
  sampling?: boolean;
  logging?: boolean;
}

export interface ServerConfiguration {
  identity: MCPServerIdentity;
  capabilities: ServerCapabilities;
  transport: TransportConfig;
  security: SecurityConfig;
  performance: PerformanceConfig;
  monitoring: MonitoringConfig;
}

// ============================================================================
// Transport and Communication
// ============================================================================

export enum TransportType {
  STDIO = 'stdio',
  HTTP = 'http',
  WEBSOCKET = 'websocket',
  GRPC = 'grpc'
}

export interface TransportConfig {
  type: TransportType;
  options: Record<string, any>;
}

export interface RequestContext {
  requestId: string;
  timestamp: Date;
  clientId?: string;
  metadata?: Record<string, any>;
}

export interface ResponseWrapper<T = any> {
  success: boolean;
  data?: T;
  error?: ErrorInfo;
  metadata?: Record<string, any>;
  requestId: string;
  timestamp: Date;
}

// ============================================================================
// Error Handling
// ============================================================================

export enum ErrorCode {
  // Protocol errors
  INVALID_REQUEST = 'INVALID_REQUEST',
  METHOD_NOT_FOUND = 'METHOD_NOT_FOUND',
  INVALID_PARAMS = 'INVALID_PARAMS',
  INTERNAL_ERROR = 'INTERNAL_ERROR',
  
  // Tool errors
  TOOL_NOT_FOUND = 'TOOL_NOT_FOUND',
  TOOL_EXECUTION_FAILED = 'TOOL_EXECUTION_FAILED',
  TOOL_TIMEOUT = 'TOOL_TIMEOUT',
  
  // Resource errors
  RESOURCE_NOT_FOUND = 'RESOURCE_NOT_FOUND',
  RESOURCE_ACCESS_DENIED = 'RESOURCE_ACCESS_DENIED',
  RESOURCE_READ_FAILED = 'RESOURCE_READ_FAILED',
  
  // Auth errors
  AUTHENTICATION_FAILED = 'AUTHENTICATION_FAILED',
  AUTHORIZATION_FAILED = 'AUTHORIZATION_FAILED',
  
  // Rate limiting
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  
  // Server errors
  SERVER_OVERLOADED = 'SERVER_OVERLOADED',
  SERVER_UNAVAILABLE = 'SERVER_UNAVAILABLE'
}

export interface ErrorInfo {
  code: ErrorCode;
  message: string;
  details?: Record<string, any>;
  stack?: string;
  retryable?: boolean;
  retryAfter?: number; // seconds
}

// ============================================================================
// Security
// ============================================================================

export interface SecurityConfig {
  authentication: AuthConfig;
  authorization: AuthzConfig;
  rateLimit: RateLimitConfig;
  cors: CorsConfig;
  tls?: TlsConfig;
}

export interface AuthConfig {
  enabled: boolean;
  type: 'jwt' | 'api_key' | 'oauth2' | 'none';
  options: Record<string, any>;
}

export interface AuthzConfig {
  enabled: boolean;
  rules: AuthzRule[];
}

export interface AuthzRule {
  resource: string;
  actions: string[];
  conditions?: Record<string, any>;
}

export interface RateLimitConfig {
  enabled: boolean;
  windowMs: number;
  maxRequests: number;
  keyGenerator?: string; // function name or identifier
}

export interface CorsConfig {
  enabled: boolean;
  origins: string[];
  methods: string[];
  headers: string[];
  credentials: boolean;
}

export interface TlsConfig {
  enabled: boolean;
  cert: string;
  key: string;
  ca?: string;
}

// ============================================================================
// Performance and Monitoring
// ============================================================================

export interface PerformanceConfig {
  timeout: number; // ms
  maxConcurrency: number;
  caching: CacheConfig;
  circuitBreaker: CircuitBreakerConfig;
}

export interface CacheConfig {
  enabled: boolean;
  type: 'memory' | 'redis' | 'file';
  ttl: number; // seconds
  maxSize?: number;
  options?: Record<string, any>;
}

export interface CircuitBreakerConfig {
  enabled: boolean;
  failureThreshold: number;
  resetTimeout: number; // ms
  monitoringPeriod: number; // ms
}

export interface MonitoringConfig {
  metrics: MetricsConfig;
  health: HealthConfig;
  logging: LoggingConfig;
}

export interface MetricsConfig {
  enabled: boolean;
  interval: number; // ms
  retention: number; // hours
  exporters: string[];
}

export interface HealthConfig {
  enabled: boolean;
  endpoint: string;
  interval: number; // ms
  checks: string[];
}

export interface LoggingConfig {
  level: 'debug' | 'info' | 'warn' | 'error';
  format: 'json' | 'text';
  output: 'console' | 'file' | 'both';
  file?: string;
  maxSize?: number; // bytes
  maxFiles?: number;
}

// ============================================================================
// Metrics and Health
// ============================================================================

export interface ServerMetrics {
  uptime: number; // seconds
  requestCount: number;
  errorCount: number;
  toolCalls: number;
  resourceAccess: number;
  lastActivity: Date;
  responseTime: {
    p50: number;
    p95: number;
    p99: number;
  };
  memory: {
    used: number;
    total: number;
    percentage: number;
  };
  cpu: {
    usage: number;
    load: number[];
  };
}

export enum HealthStatus {
  HEALTHY = 'healthy',
  DEGRADED = 'degraded',
  UNHEALTHY = 'unhealthy'
}

export enum CheckStatus {
  PASS = 'pass',
  FAIL = 'fail',
  WARN = 'warn'
}

export interface HealthCheck {
  name: string;
  status: CheckStatus;
  message?: string;
  duration?: number; // ms
  metadata?: Record<string, any>;
}

export interface HealthReport {
  status: HealthStatus;
  timestamp: Date;
  checks: HealthCheck[];
  metrics: ServerMetrics;
  dependencies?: HealthReport[];
}

// ============================================================================
// Service Discovery
// ============================================================================

export interface ServiceRegistry {
  register(service: ServiceInfo): Promise<void>;
  unregister(serviceId: string): Promise<void>;
  discover(serviceType: string): Promise<ServiceInfo[]>;
  watch(serviceType: string, callback: (services: ServiceInfo[]) => void): void;
}

export interface ServiceInfo {
  id: string;
  name: string;
  version: string;
  type: string;
  endpoint: string;
  metadata: Record<string, any>;
  health: HealthStatus;
  registeredAt: Date;
  lastSeen: Date;
  tags: string[];
}

export interface LoadBalancer {
  selectService(services: ServiceInfo[]): ServiceInfo | null;
  updateWeights(weights: Record<string, number>): void;
}

// ============================================================================
// Development and Testing
// ============================================================================

export interface TestConfig {
  enabled: boolean;
  mockServices: boolean;
  testData: Record<string, any>;
  coverage: boolean;
}

export interface DeploymentInfo {
  environment: 'development' | 'staging' | 'production';
  version: string;
  buildTime: Date;
  commitHash?: string;
  deployedBy?: string;
  deployedAt: Date;
}

// ============================================================================
// Event System
// ============================================================================

export interface EventEmitter {
  on(event: string, listener: (...args: any[]) => void): void;
  off(event: string, listener: (...args: any[]) => void): void;
  emit(event: string, ...args: any[]): void;
  once(event: string, listener: (...args: any[]) => void): void;
}

export interface ServerEvent {
  type: string;
  timestamp: Date;
  serverId: string;
  data: Record<string, any>;
}

// ============================================================================
// Plugin System
// ============================================================================

export interface Plugin {
  name: string;
  version: string;
  dependencies: string[];
  install(server: any): Promise<void>;
  uninstall(server: any): Promise<void>;
  configure(config: Record<string, any>): void;
}

export interface PluginManager {
  register(plugin: Plugin): void;
  unregister(pluginName: string): void;
  getPlugin(name: string): Plugin | null;
  listPlugins(): Plugin[];
  enablePlugin(name: string): Promise<void>;
  disablePlugin(name: string): Promise<void>;
}

// ============================================================================
// Utility Types
// ============================================================================

export type AsyncFunction<T = any> = (...args: any[]) => Promise<T>;
export type SyncFunction<T = any> = (...args: any[]) => T;
export type MaybeAsync<T = any> = T | Promise<T>;

export interface Disposable {
  dispose(): void | Promise<void>;
}

export interface Initializable {
  initialize(): Promise<void>;
}

export interface Configurable<T = any> {
  configure(config: T): void;
}

// ============================================================================
// Constants
// ============================================================================

export const MCP_PROTOCOL_VERSION = '1.0.0';
export const DEFAULT_TIMEOUT = 30000; // 30 seconds
export const DEFAULT_MAX_CONCURRENCY = 100;
export const DEFAULT_RATE_LIMIT = { windowMs: 60000, maxRequests: 1000 };
export const DEFAULT_HEALTH_CHECK_INTERVAL = 30000; // 30 seconds
export const DEFAULT_METRICS_INTERVAL = 10000; // 10 seconds