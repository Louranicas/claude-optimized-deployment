/**
 * TypeScript MCP Server Template
 * 
 * This template provides a complete example of how to implement
 * an MCP server using the standardized TypeScript base class.
 */

import { BaseMCPServer, MCPServerOptions } from '../src/core/base-server';
import { Tool, Resource } from '@modelcontextprotocol/sdk/types.js';
import { createEnhancedLogger } from '../src/core/logger';
import { configUtils } from '../src/core/config-manager';

// Server-specific configuration interface
interface TemplateServerConfig {
  // Add your server-specific configuration options here
  apiEndpoint?: string;
  apiKey?: string;
  maxRetries?: number;
  cacheEnabled?: boolean;
}

/**
 * Template MCP Server
 * 
 * Replace 'TemplateServer' with your actual server name and implement
 * the required abstract methods with your specific business logic.
 */
export class TemplateServer extends BaseMCPServer {
  private config: TemplateServerConfig;

  constructor(options: MCPServerOptions & { serverConfig?: TemplateServerConfig }) {
    super(options);
    
    // Load server-specific configuration
    this.config = {
      apiEndpoint: 'https://api.example.com',
      apiKey: process.env.TEMPLATE_API_KEY || '',
      maxRetries: 3,
      cacheEnabled: true,
      ...options.serverConfig,
    };
    
    // Setup enhanced logging
    this.logger = createEnhancedLogger(options.name, {
      version: options.version,
      config: this.config,
    });
    
    this.logger.info('Template server initialized', { config: this.config });
  }

  /**
   * Setup server-specific tools
   * 
   * Register all tools that this server provides.
   * Each tool should have a clear name, description, and input schema.
   */
  protected async setupTools(): Promise<void> {
    // Example tool: Echo
    const echoTool: Tool = {
      name: 'echo',
      description: 'Echo back the provided message',
      inputSchema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            description: 'The message to echo back',
          },
          uppercase: {
            type: 'boolean',
            description: 'Whether to convert the message to uppercase',
            default: false,
          },
        },
        required: ['message'],
      },
    };
    this.registerTool(echoTool);

    // Example tool: API Call
    const apiCallTool: Tool = {
      name: 'api_call',
      description: 'Make a call to the configured API endpoint',
      inputSchema: {
        type: 'object',
        properties: {
          endpoint: {
            type: 'string',
            description: 'API endpoint path (relative to base URL)',
          },
          method: {
            type: 'string',
            enum: ['GET', 'POST', 'PUT', 'DELETE'],
            default: 'GET',
            description: 'HTTP method to use',
          },
          data: {
            type: 'object',
            description: 'Request body data for POST/PUT requests',
          },
        },
        required: ['endpoint'],
      },
    };
    this.registerTool(apiCallTool);

    // Example tool: Generate UUID
    const generateUuidTool: Tool = {
      name: 'generate_uuid',
      description: 'Generate a random UUID',
      inputSchema: {
        type: 'object',
        properties: {
          version: {
            type: 'number',
            enum: [1, 4],
            default: 4,
            description: 'UUID version to generate',
          },
        },
      },
    };
    this.registerTool(generateUuidTool);

    this.logger.info(`Registered ${this.tools.size} tools`);
  }

  /**
   * Setup server-specific resources
   * 
   * Register all resources that this server provides.
   * Resources can be files, data endpoints, or any readable content.
   */
  protected async setupResources(): Promise<void> {
    // Example resource: Server info
    const serverInfoResource: Resource = {
      uri: 'template://server/info',
      name: 'Server Information',
      description: 'Information about this server instance',
      mimeType: 'application/json',
    };
    this.registerResource(serverInfoResource);

    // Example resource: Configuration
    const configResource: Resource = {
      uri: 'template://server/config',
      name: 'Server Configuration',
      description: 'Current server configuration (sanitized)',
      mimeType: 'application/json',
    };
    this.registerResource(configResource);

    // Example resource: Logs
    const logsResource: Resource = {
      uri: 'template://server/logs',
      name: 'Server Logs',
      description: 'Recent server log entries',
      mimeType: 'text/plain',
    };
    this.registerResource(logsResource);

    this.logger.info(`Registered ${this.resources.size} resources`);
  }

  /**
   * Execute a tool with the given arguments
   * 
   * This method is called when a client wants to execute one of
   * the tools registered by this server.
   */
  protected async executeTool(name: string, args: unknown): Promise<unknown> {
    const startTime = Date.now();
    
    try {
      switch (name) {
        case 'echo':
          return await this.executeEchoTool(args as { message: string; uppercase?: boolean });
        
        case 'api_call':
          return await this.executeApiCallTool(args as { endpoint: string; method?: string; data?: any });
        
        case 'generate_uuid':
          return await this.executeGenerateUuidTool(args as { version?: number });
        
        default:
          throw new Error(`Unknown tool: ${name}`);
      }
    } finally {
      const duration = Date.now() - startTime;
      this.logger.logPerformance(`tool_${name}`, duration, { args });
    }
  }

  /**
   * Read resource content
   * 
   * This method is called when a client wants to read the content
   * of one of the resources registered by this server.
   */
  protected async readResource(uri: string): Promise<{ uri: string; mimeType?: string; text?: string; blob?: string }> {
    const startTime = Date.now();
    
    try {
      switch (uri) {
        case 'template://server/info':
          return {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify({
              name: this.options.name,
              version: this.options.version,
              description: this.options.description,
              uptime: this.metrics.uptime,
              requestCount: this.metrics.requestCount,
              toolCount: this.tools.size,
              resourceCount: this.resources.size,
            }, null, 2),
          };
        
        case 'template://server/config':
          return {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify({
              ...this.config,
              apiKey: this.config.apiKey ? '***' : undefined, // Sanitize sensitive data
            }, null, 2),
          };
        
        case 'template://server/logs':
          return {
            uri,
            mimeType: 'text/plain',
            text: 'Log entries would be retrieved from your logging system here...',
          };
        
        default:
          throw new Error(`Unknown resource: ${uri}`);
      }
    } finally {
      const duration = Date.now() - startTime;
      this.logger.logPerformance(`resource_read`, duration, { uri });
    }
  }

  /**
   * Cleanup resources before shutdown
   * 
   * Perform any necessary cleanup operations before the server shuts down.
   */
  protected async cleanup(): Promise<void> {
    this.logger.info('Performing cleanup...');
    
    // Close database connections, file handles, etc.
    // Cancel ongoing operations
    // Save state if necessary
    
    this.logger.info('Cleanup completed');
  }

  // ========================================================================
  // Tool Implementation Methods
  // ========================================================================

  private async executeEchoTool(args: { message: string; uppercase?: boolean }): Promise<{ echo: string; originalLength: number; processedAt: string }> {
    const { message, uppercase = false } = args;
    
    this.logger.info('Executing echo tool', { messageLength: message.length, uppercase });
    
    const processedMessage = uppercase ? message.toUpperCase() : message;
    
    return {
      echo: processedMessage,
      originalLength: message.length,
      processedAt: new Date().toISOString(),
    };
  }

  private async executeApiCallTool(args: { endpoint: string; method?: string; data?: any }): Promise<any> {
    const { endpoint, method = 'GET', data } = args;
    
    this.logger.info('Executing API call tool', { endpoint, method });
    
    // Validate API key
    if (!this.config.apiKey) {
      throw new Error('API key not configured');
    }
    
    const url = `${this.config.apiEndpoint}${endpoint}`;
    
    // Simulate API call (replace with actual HTTP client)
    const response = {
      url,
      method,
      data,
      timestamp: new Date().toISOString(),
      simulated: true,
      message: 'This is a simulated API response. Replace with actual HTTP client implementation.',
    };
    
    this.logger.info('API call completed', { url, method, responseSize: JSON.stringify(response).length });
    
    return response;
  }

  private async executeGenerateUuidTool(args: { version?: number }): Promise<{ uuid: string; version: number; generatedAt: string }> {
    const { version = 4 } = args;
    
    this.logger.info('Generating UUID', { version });
    
    let uuid: string;
    
    if (version === 4) {
      // Generate UUID v4 (random)
      uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
      });
    } else if (version === 1) {
      // Simplified UUID v1 (timestamp-based)
      const timestamp = Date.now().toString(16);
      uuid = `${timestamp.slice(-8)}-${timestamp.slice(-12, -8)}-1xxx-yxxx-xxxxxxxxxxxx`.replace(/[xy]/g, (c) => {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
      });
    } else {
      throw new Error(`Unsupported UUID version: ${version}`);
    }
    
    return {
      uuid,
      version,
      generatedAt: new Date().toISOString(),
    };
  }

  // ========================================================================
  // Custom Health Checks
  // ========================================================================

  /**
   * Add custom health checks specific to this server
   */
  public setupCustomHealthChecks(): void {
    // API connectivity check
    this.addHealthCheck('api_connectivity', async () => {
      try {
        // Simulate API health check
        const healthy = this.config.apiKey !== '';
        
        return {
          name: 'api_connectivity',
          status: healthy ? 'pass' : 'fail',
          message: healthy ? 'API is accessible' : 'API key not configured',
        };
      } catch (error) {
        return {
          name: 'api_connectivity',
          status: 'fail',
          message: `API health check failed: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    });

    // Configuration check
    this.addHealthCheck('configuration', async () => {
      const issues: string[] = [];
      
      if (!this.config.apiEndpoint) {
        issues.push('API endpoint not configured');
      }
      
      if (!this.config.apiKey) {
        issues.push('API key not configured');
      }
      
      return {
        name: 'configuration',
        status: issues.length === 0 ? 'pass' : 'warn',
        message: issues.length === 0 ? 'Configuration is valid' : `Configuration issues: ${issues.join(', ')}`,
      };
    });
  }
}

// ============================================================================
// Server Factory and Startup
// ============================================================================

/**
 * Create and configure a template server instance
 */
export async function createTemplateServer(config?: Partial<TemplateServerConfig>): Promise<TemplateServer> {
  // Load configuration
  const serverConfig = await configUtils.loadWithDefaults();
  
  // Create server instance
  const server = new TemplateServer({
    name: 'template-server',
    version: '1.0.0',
    description: 'A template MCP server demonstrating best practices',
    serverConfig: config,
  });
  
  // Setup custom health checks
  server.setupCustomHealthChecks();
  
  return server;
}

/**
 * Main entry point for the server
 */
export async function main(): Promise<void> {
  try {
    const server = await createTemplateServer();
    
    // Setup graceful shutdown
    process.on('SIGTERM', () => server.gracefulShutdown());
    process.on('SIGINT', () => server.gracefulShutdown());
    
    // Start the server
    await server.start();
    
    console.log('Template MCP Server started successfully');
    
  } catch (error) {
    console.error('Failed to start Template MCP Server:', error);
    process.exit(1);
  }
}

// Run the server if this file is executed directly
if (require.main === module) {
  main().catch(console.error);
}