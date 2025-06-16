import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { Tool, Resource } from '@modelcontextprotocol/sdk/types.js';
import { createServerLogger } from './logger';
import { Logger } from 'pino';
import { MCPServerConfig } from './config';
import { EventEmitter } from 'events';

// Common interface definitions for cross-language compatibility
export interface MCPServerOptions {
  name: string;
  version: string;
  description: string;
  config?: Partial<MCPServerConfig>;
  capabilities?: ServerCapabilities;
}

export interface ServerCapabilities {
  tools?: boolean;
  resources?: boolean;
  prompts?: boolean;
  roots?: boolean;
  sampling?: boolean;
}

export interface ServerMetrics {
  uptime: number;
  requestCount: number;
  errorCount: number;
  toolCalls: number;
  resourceAccess: number;
  lastActivity: Date;
}

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: Date;
  checks: HealthCheck[];
  metrics: ServerMetrics;
}

export interface HealthCheck {
  name: string;
  status: 'pass' | 'fail' | 'warn';
  message?: string;
  duration?: number;
}

export abstract class BaseMCPServer extends EventEmitter {
  protected server: Server;
  protected logger: Logger;
  protected tools: Map<string, Tool> = new Map();
  protected resources: Map<string, Resource> = new Map();
  protected metrics: ServerMetrics;
  protected healthChecks: Map<string, () => Promise<HealthCheck>> = new Map();
  protected isStarted: boolean = false;
  
  constructor(protected options: MCPServerOptions) {
    super();
    this.logger = createServerLogger(options.name);
    
    // Initialize metrics
    this.metrics = {
      uptime: 0,
      requestCount: 0,
      errorCount: 0,
      toolCalls: 0,
      resourceAccess: 0,
      lastActivity: new Date()
    };
    
    // Create server with enhanced capabilities
    this.server = new Server(
      {
        name: options.name,
        version: options.version,
      },
      {
        capabilities: {
          tools: options.capabilities?.tools ? {} : undefined,
          resources: options.capabilities?.resources ? {} : undefined,
          prompts: options.capabilities?.prompts ? {} : undefined,
          roots: options.capabilities?.roots ? {} : undefined,
          sampling: options.capabilities?.sampling ? {} : undefined,
        },
      }
    );
    
    this.setupErrorHandling();
    this.setupMetrics();
    this.registerStandardHealthChecks();
  }
  
  private setupErrorHandling(): void {
    this.server.onerror = (error) => {
      this.metrics.errorCount++;
      this.logger.error({ error }, 'Server error occurred');
      this.emit('error', error);
    };
    
    process.on('unhandledRejection', (reason, promise) => {
      this.metrics.errorCount++;
      this.logger.error({ reason, promise }, 'Unhandled rejection');
      this.emit('error', new Error(`Unhandled rejection: ${reason}`));
    });
    
    process.on('uncaughtException', (error) => {
      this.metrics.errorCount++;
      this.logger.error({ error }, 'Uncaught exception');
      this.emit('error', error);
      // Graceful shutdown instead of immediate exit
      this.gracefulShutdown();
    });
  }
  
  private setupMetrics(): void {
    const startTime = Date.now();
    
    // Update uptime every second
    setInterval(() => {
      this.metrics.uptime = Math.floor((Date.now() - startTime) / 1000);
    }, 1000);
  }
  
  private registerStandardHealthChecks(): void {
    // Memory usage check
    this.healthChecks.set('memory', async () => {
      const usage = process.memoryUsage();
      const heapUsedMB = Math.round(usage.heapUsed / 1024 / 1024);
      const heapTotalMB = Math.round(usage.heapTotal / 1024 / 1024);
      const usage_percent = (heapUsedMB / heapTotalMB) * 100;
      
      return {
        name: 'memory',
        status: usage_percent > 90 ? 'fail' : usage_percent > 75 ? 'warn' : 'pass',
        message: `Heap usage: ${heapUsedMB}MB/${heapTotalMB}MB (${usage_percent.toFixed(1)}%)`,
      };
    });
    
    // Server status check
    this.healthChecks.set('server', async () => {
      return {
        name: 'server',
        status: this.isStarted ? 'pass' : 'fail',
        message: this.isStarted ? 'Server is running' : 'Server is not started',
      };
    });
  }
  
  protected registerTool(tool: Tool): void {
    this.tools.set(tool.name, tool);
    this.logger.info({ toolName: tool.name }, 'Tool registered');
    this.emit('tool_registered', tool);
  }
  
  protected registerResource(resource: Resource): void {
    this.resources.set(resource.uri, resource);
    this.logger.info({ resourceUri: resource.uri }, 'Resource registered');
    this.emit('resource_registered', resource);
  }
  
  protected addHealthCheck(name: string, check: () => Promise<HealthCheck>): void {
    this.healthChecks.set(name, check);
    this.logger.info({ checkName: name }, 'Health check registered');
  }
  
  public async start(): Promise<void> {
    try {
      // Setup server-specific components
      await this.setupTools();
      await this.setupResources();
      
      this.setupRequestHandlers();
      
      // Start the server
      const transport = new StdioServerTransport();
      await this.server.connect(transport);
      
      this.isStarted = true;
      this.emit('started');
      
      this.logger.info(
        { 
          name: this.options.name, 
          version: this.options.version,
          toolCount: this.tools.size,
          resourceCount: this.resources.size
        }, 
        'MCP server started'
      );
    } catch (error) {
      this.logger.error({ error }, 'Failed to start server');
      this.emit('start_failed', error);
      throw error;
    }
  }
  
  private setupRequestHandlers(): void {
    // Tools handlers
    this.server.setRequestHandler('tools/list' as any, async () => {
      this.metrics.requestCount++;
      this.metrics.lastActivity = new Date();
      return { tools: Array.from(this.tools.values()) };
    });
    
    this.server.setRequestHandler('tools/call' as any, async (request: any) => {
      this.metrics.requestCount++;
      this.metrics.toolCalls++;
      this.metrics.lastActivity = new Date();
      
      const { name, arguments: args } = request.params as {
        name: string;
        arguments?: unknown;
      };
      
      const tool = this.tools.get(name);
      if (!tool) {
        this.metrics.errorCount++;
        throw new Error(`Tool ${name} not found`);
      }
      
      this.logger.info({ toolName: name, args }, 'Tool called');
      
      try {
        const result = await this.executeTool(name, args);
        this.emit('tool_executed', { name, args, result });
        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      } catch (error) {
        this.metrics.errorCount++;
        this.logger.error({ error, toolName: name }, 'Tool execution failed');
        this.emit('tool_failed', { name, args, error });
        throw error;
      }
    });
    
    // Resources handlers
    this.server.setRequestHandler('resources/list' as any, async () => {
      this.metrics.requestCount++;
      this.metrics.lastActivity = new Date();
      return { resources: Array.from(this.resources.values()) };
    });
    
    this.server.setRequestHandler('resources/read' as any, async (request: any) => {
      this.metrics.requestCount++;
      this.metrics.resourceAccess++;
      this.metrics.lastActivity = new Date();
      
      const { uri } = request.params as { uri: string };
      
      const resource = this.resources.get(uri);
      if (!resource) {
        this.metrics.errorCount++;
        throw new Error(`Resource ${uri} not found`);
      }
      
      try {
        const content = await this.readResource(uri);
        this.emit('resource_read', { uri, content });
        return { contents: [content] };
      } catch (error) {
        this.metrics.errorCount++;
        this.logger.error({ error, uri }, 'Resource read failed');
        this.emit('resource_failed', { uri, error });
        throw error;
      }
    });
  }
  
  public async getHealth(): Promise<HealthStatus> {
    const checks: HealthCheck[] = [];
    
    for (const [name, checkFn] of this.healthChecks) {
      try {
        const start = Date.now();
        const check = await checkFn();
        check.duration = Date.now() - start;
        checks.push(check);
      } catch (error) {
        checks.push({
          name,
          status: 'fail',
          message: `Health check failed: ${error instanceof Error ? error.message : String(error)}`,
        });
      }
    }
    
    const hasFailures = checks.some(check => check.status === 'fail');
    const hasWarnings = checks.some(check => check.status === 'warn');
    
    return {
      status: hasFailures ? 'unhealthy' : hasWarnings ? 'degraded' : 'healthy',
      timestamp: new Date(),
      checks,
      metrics: { ...this.metrics },
    };
  }
  
  public async gracefulShutdown(): Promise<void> {
    this.logger.info('Starting graceful shutdown');
    this.emit('shutdown_started');
    
    try {
      // Perform cleanup operations
      await this.cleanup();
      
      // Close server connections
      if (this.server) {
        await this.server.close();
      }
      
      this.isStarted = false;
      this.emit('shutdown_complete');
      this.logger.info('Graceful shutdown completed');
    } catch (error) {
      this.logger.error({ error }, 'Error during graceful shutdown');
      this.emit('shutdown_error', error);
    } finally {
      process.exit(0);
    }
  }
  
  // Abstract methods that must be implemented by concrete servers
  protected abstract setupTools(): Promise<void>;
  protected abstract setupResources(): Promise<void>;
  protected abstract executeTool(name: string, args: unknown): Promise<unknown>;
  protected abstract readResource(uri: string): Promise<{ uri: string; mimeType?: string; text?: string; blob?: string }>;
  protected abstract cleanup(): Promise<void>;
}