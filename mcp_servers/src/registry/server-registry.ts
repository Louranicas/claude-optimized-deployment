import { EventEmitter } from 'events';
import { createServerLogger } from '../core/logger';
import { ChildProcess, spawn } from 'child_process';
import path from 'path';
import fs from 'fs/promises';

export interface MCPServerInfo {
  name: string;
  version: string;
  description: string;
  status: 'stopped' | 'starting' | 'running' | 'error';
  pid?: number;
  startTime?: Date;
  endpoint?: string;
  capabilities: string[];
  tools: string[];
}

export interface MCPServerConfig {
  name: string;
  path: string;
  env?: Record<string, string>;
  args?: string[];
  autoStart?: boolean;
  restartOnFailure?: boolean;
  maxRestarts?: number;
}

export class MCPServerRegistry extends EventEmitter {
  private servers: Map<string, MCPServerInfo> = new Map();
  private processes: Map<string, ChildProcess> = new Map();
  private configs: Map<string, MCPServerConfig> = new Map();
  private restartCounts: Map<string, number> = new Map();
  private logger = createServerLogger('registry');
  
  constructor() {
    super();
    this.loadServerConfigs();
  }
  
  private async loadServerConfigs() {
    // Define core server configurations
    const coreServers: MCPServerConfig[] = [
      {
        name: 'development-workflow',
        path: path.join(__dirname, '../servers/development-workflow/index.ts'),
        autoStart: true,
        restartOnFailure: true,
        maxRestarts: 3,
      },
      {
        name: 'search-integration',
        path: path.join(__dirname, '../servers/search-integration/index.ts'),
        autoStart: true,
        restartOnFailure: true,
        maxRestarts: 3,
      },
      {
        name: 'ai-enhancement',
        path: path.join(__dirname, '../servers/ai-enhancement/index.ts'),
        autoStart: true,
        restartOnFailure: true,
        maxRestarts: 3,
      },
      {
        name: 'code-analysis',
        path: path.join(__dirname, '../servers/code-analysis/index.ts'),
        autoStart: false,
        restartOnFailure: true,
        maxRestarts: 3,
      },
      {
        name: 'documentation-generation',
        path: path.join(__dirname, '../servers/documentation-generation/index.ts'),
        autoStart: false,
        restartOnFailure: true,
        maxRestarts: 3,
      },
    ];
    
    // Register core servers
    for (const config of coreServers) {
      await this.registerServer(config);
    }
    
    // Load custom server configs from file if exists
    try {
      const configPath = path.join(__dirname, '../../config/custom-servers.json');
      const customConfigs = await fs.readFile(configPath, 'utf-8');
      const customServers = JSON.parse(customConfigs) as MCPServerConfig[];
      
      for (const config of customServers) {
        await this.registerServer(config);
      }
    } catch (error) {
      // No custom servers configured
      this.logger.debug('No custom server configurations found');
    }
  }
  
  async registerServer(config: MCPServerConfig): Promise<void> {
    this.configs.set(config.name, config);
    
    // Initialize server info
    const info: MCPServerInfo = {
      name: config.name,
      version: '1.0.0',
      description: `MCP ${config.name} server`,
      status: 'stopped',
      capabilities: [],
      tools: [],
    };
    
    this.servers.set(config.name, info);
    this.restartCounts.set(config.name, 0);
    
    this.logger.info({ server: config.name }, 'Server registered');
    this.emit('server:registered', config.name);
    
    // Auto-start if configured
    if (config.autoStart) {
      await this.startServer(config.name);
    }
  }
  
  async startServer(name: string): Promise<void> {
    const config = this.configs.get(name);
    const info = this.servers.get(name);
    
    if (!config || !info) {
      throw new Error(`Server ${name} not found`);
    }
    
    if (info.status === 'running') {
      this.logger.warn({ server: name }, 'Server already running');
      return;
    }
    
    info.status = 'starting';
    this.emit('server:starting', name);
    
    try {
      // Check if the server file exists
      await fs.access(config.path);
      
      // Spawn the server process
      const args = ['--experimental-specifier-resolution=node', config.path, ...(config.args || [])];
      const proc = spawn('ts-node', args, {
        env: {
          ...process.env,
          ...config.env,
          MCP_SERVER_NAME: name,
        },
        stdio: ['pipe', 'pipe', 'pipe', 'ipc'],
      });
      
      proc.stdout?.on('data', (data) => {
        this.logger.debug({ server: name, data: data.toString() }, 'Server output');
      });
      
      proc.stderr?.on('data', (data) => {
        this.logger.error({ server: name, error: data.toString() }, 'Server error');
      });
      
      proc.on('exit', (code, signal) => {
        this.handleServerExit(name, code, signal);
      });
      
      proc.on('error', (error) => {
        this.logger.error({ server: name, error }, 'Failed to start server');
        info.status = 'error';
        this.emit('server:error', name, error);
      });
      
      // Store process reference
      this.processes.set(name, proc);
      
      // Update server info
      info.status = 'running';
      info.pid = proc.pid;
      info.startTime = new Date();
      
      // Wait for server to be ready (simplified - in production use IPC)
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Fetch server capabilities
      await this.fetchServerCapabilities(name);
      
      this.logger.info({ server: name, pid: proc.pid }, 'Server started');
      this.emit('server:started', name);
      
    } catch (error) {
      this.logger.error({ server: name, error }, 'Failed to start server');
      info.status = 'error';
      this.emit('server:error', name, error);
      throw error;
    }
  }
  
  async stopServer(name: string): Promise<void> {
    const proc = this.processes.get(name);
    const info = this.servers.get(name);
    
    if (!proc || !info) {
      throw new Error(`Server ${name} not found or not running`);
    }
    
    this.logger.info({ server: name }, 'Stopping server');
    this.emit('server:stopping', name);
    
    // Send graceful shutdown signal
    proc.kill('SIGTERM');
    
    // Wait for process to exit (with timeout)
    await new Promise<void>((resolve) => {
      const timeout = setTimeout(() => {
        this.logger.warn({ server: name }, 'Server did not stop gracefully, forcing');
        proc.kill('SIGKILL');
        resolve();
      }, 5000);
      
      proc.once('exit', () => {
        clearTimeout(timeout);
        resolve();
      });
    });
    
    // Clean up
    this.processes.delete(name);
    info.status = 'stopped';
    info.pid = undefined;
    info.startTime = undefined;
    
    this.logger.info({ server: name }, 'Server stopped');
    this.emit('server:stopped', name);
  }
  
  async restartServer(name: string): Promise<void> {
    await this.stopServer(name);
    await this.startServer(name);
  }
  
  private async handleServerExit(name: string, code: number | null, signal: string | null) {
    const config = this.configs.get(name);
    const info = this.servers.get(name);
    
    if (!config || !info) return;
    
    this.processes.delete(name);
    info.status = 'stopped';
    info.pid = undefined;
    
    this.logger.warn(
      { server: name, code, signal },
      'Server exited'
    );
    
    this.emit('server:exited', name, code, signal);
    
    // Handle automatic restart
    if (config.restartOnFailure && code !== 0) {
      const restartCount = this.restartCounts.get(name) || 0;
      
      if (restartCount < (config.maxRestarts || 3)) {
        this.restartCounts.set(name, restartCount + 1);
        this.logger.info(
          { server: name, attempt: restartCount + 1 },
          'Attempting to restart server'
        );
        
        setTimeout(() => {
          this.startServer(name).catch((error) => {
            this.logger.error({ server: name, error }, 'Failed to restart server');
          });
        }, 5000); // Wait 5 seconds before restart
      } else {
        this.logger.error(
          { server: name },
          'Maximum restart attempts reached'
        );
        info.status = 'error';
        this.emit('server:failed', name);
      }
    }
  }
  
  private async fetchServerCapabilities(name: string): Promise<void> {
    const info = this.servers.get(name);
    if (!info) return;
    
    try {
      // In a real implementation, this would communicate with the server
      // via IPC or HTTP to get actual capabilities
      
      // For now, define capabilities based on server type
      switch (name) {
        case 'development-workflow':
          info.capabilities = ['project-creation', 'boilerplate-generation', 'environment-setup'];
          info.tools = ['create_project_structure', 'run_dev_command', 'generate_boilerplate', 'setup_dev_environment'];
          break;
        case 'search-integration':
          info.capabilities = ['web-search', 'code-search', 'research'];
          info.tools = ['web_search', 'code_search', 'research_assistant', 'realtime_info'];
          break;
        case 'ai-enhancement':
          info.capabilities = ['text-enhancement', 'code-enhancement', 'idea-generation'];
          info.tools = ['enhance_text', 'enhance_code', 'generate_ideas', 'solve_problem', 'learning_assistant'];
          break;
        case 'code-analysis':
          info.capabilities = ['static-analysis', 'complexity-analysis', 'security-scanning'];
          info.tools = ['analyze_code', 'find_issues', 'calculate_metrics', 'security_scan'];
          break;
        case 'documentation-generation':
          info.capabilities = ['api-docs', 'readme-generation', 'inline-comments'];
          info.tools = ['generate_docs', 'update_readme', 'add_comments', 'create_api_docs'];
          break;
      }
    } catch (error) {
      this.logger.error({ server: name, error }, 'Failed to fetch server capabilities');
    }
  }
  
  getServer(name: string): MCPServerInfo | undefined {
    return this.servers.get(name);
  }
  
  getAllServers(): MCPServerInfo[] {
    return Array.from(this.servers.values());
  }
  
  getRunningServers(): MCPServerInfo[] {
    return this.getAllServers().filter(s => s.status === 'running');
  }
  
  async startAll(): Promise<void> {
    const servers = Array.from(this.configs.keys());
    
    for (const name of servers) {
      try {
        await this.startServer(name);
      } catch (error) {
        this.logger.error({ server: name, error }, 'Failed to start server');
      }
    }
  }
  
  async stopAll(): Promise<void> {
    const runningServers = this.getRunningServers();
    
    for (const server of runningServers) {
      try {
        await this.stopServer(server.name);
      } catch (error) {
        this.logger.error({ server: server.name, error }, 'Failed to stop server');
      }
    }
  }
  
  async getServerStatus(): Promise<Record<string, any>> {
    const status = {
      totalServers: this.servers.size,
      runningServers: this.getRunningServers().length,
      servers: {} as Record<string, any>,
    };
    
    for (const [name, info] of this.servers) {
      status.servers[name] = {
        ...info,
        uptime: info.startTime ? Date.now() - info.startTime.getTime() : 0,
        restartCount: this.restartCounts.get(name) || 0,
      };
    }
    
    return status;
  }
  
  // Graceful shutdown
  async shutdown(): Promise<void> {
    this.logger.info('Shutting down MCP server registry');
    
    // Stop all servers
    await this.stopAll();
    
    // Clear all data
    this.servers.clear();
    this.processes.clear();
    this.configs.clear();
    this.restartCounts.clear();
    
    this.removeAllListeners();
  }
}

// Export singleton instance
export const registry = new MCPServerRegistry();