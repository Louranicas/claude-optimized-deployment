/**
 * Configuration Management System
 * 
 * Standardized configuration handling with validation, environment overrides,
 * and hot-reload capabilities for MCP servers.
 */

import { EventEmitter } from 'events';
import { readFileSync, watchFile } from 'fs';
import { validateObject, ValidationRule, commonValidators } from './utils';
import { ServerConfiguration } from './interfaces';

export interface ConfigManagerOptions {
  configPath?: string;
  envPrefix?: string;
  watchForChanges?: boolean;
  validateOnLoad?: boolean;
  secretsPath?: string;
}

export class ConfigManager extends EventEmitter {
  private config: ServerConfiguration | null = null;
  private configPath: string;
  private envPrefix: string;
  private watchForChanges: boolean;
  private validateOnLoad: boolean;
  private secretsPath?: string;
  private validationRules: ValidationRule[] = [];

  constructor(options: ConfigManagerOptions = {}) {
    super();
    
    this.configPath = options.configPath || process.env.MCP_CONFIG_PATH || './config.json';
    this.envPrefix = options.envPrefix || 'MCP_';
    this.watchForChanges = options.watchForChanges ?? true;
    this.validateOnLoad = options.validateOnLoad ?? true;
    this.secretsPath = options.secretsPath;
    
    this.setupValidationRules();
  }

  private setupValidationRules(): void {
    this.validationRules = [
      // Identity validation
      { field: 'identity.name', validate: commonValidators.string, required: true },
      { field: 'identity.version', validate: commonValidators.string, required: true },
      { field: 'identity.description', validate: commonValidators.string, required: true },
      
      // Transport validation
      { field: 'transport.type', validate: (v) => ['stdio', 'http', 'websocket', 'grpc'].includes(v) || 'Invalid transport type', required: true },
      { field: 'transport.options', validate: commonValidators.object, required: true },
      
      // Security validation
      { field: 'security.authentication.enabled', validate: commonValidators.boolean, required: true },
      { field: 'security.rateLimit.enabled', validate: commonValidators.boolean, required: true },
      { field: 'security.rateLimit.windowMs', validate: commonValidators.number },
      { field: 'security.rateLimit.maxRequests', validate: commonValidators.number },
      
      // Performance validation
      { field: 'performance.timeout', validate: commonValidators.range(1000, 300000) },
      { field: 'performance.maxConcurrency', validate: commonValidators.range(1, 1000) },
    ];
  }

  public async loadConfig(): Promise<ServerConfiguration> {
    try {
      // Load base configuration
      let config = await this.loadBaseConfig();
      
      // Apply environment overrides
      config = this.applyEnvironmentOverrides(config);
      
      // Load secrets if configured
      if (this.secretsPath) {
        config = await this.applySecrets(config);
      }
      
      // Validate configuration
      if (this.validateOnLoad) {
        this.validateConfig(config);
      }
      
      // Store and emit
      const previousConfig = this.config;
      this.config = config;
      
      if (previousConfig) {
        this.emit('config-changed', config, previousConfig);
      } else {
        this.emit('config-loaded', config);
      }
      
      // Setup file watching
      if (this.watchForChanges) {
        this.setupFileWatching();
      }
      
      return config;
    } catch (error) {
      this.emit('config-error', error);
      throw error;
    }
  }

  private async loadBaseConfig(): Promise<ServerConfiguration> {
    try {
      const configData = readFileSync(this.configPath, 'utf-8');
      return JSON.parse(configData);
    } catch (error) {
      if ((error as any).code === 'ENOENT') {
        // Return default configuration if file doesn't exist
        return this.getDefaultConfig();
      }
      throw new Error(`Failed to load configuration from ${this.configPath}: ${error}`);
    }
  }

  private applyEnvironmentOverrides(config: ServerConfiguration): ServerConfiguration {
    const result = JSON.parse(JSON.stringify(config)); // Deep clone
    
    // Apply environment variable overrides
    for (const [key, value] of Object.entries(process.env)) {
      if (key.startsWith(this.envPrefix) && value !== undefined) {
        const configPath = key.substring(this.envPrefix.length).toLowerCase();
        this.setNestedValue(result, configPath, this.parseEnvironmentValue(value));
      }
    }
    
    return result;
  }

  private async applySecrets(config: ServerConfiguration): Promise<ServerConfiguration> {
    if (!this.secretsPath) return config;
    
    try {
      const secretsData = readFileSync(this.secretsPath, 'utf-8');
      const secrets = JSON.parse(secretsData);
      
      // Merge secrets into configuration
      return this.deepMerge(config, secrets);
    } catch (error) {
      console.warn(`Failed to load secrets from ${this.secretsPath}: ${error}`);
      return config;
    }
  }

  private validateConfig(config: ServerConfiguration): void {
    const result = validateObject(config as any, this.validationRules);
    
    if (!result.valid) {
      throw new Error(`Configuration validation failed:\n${result.errors.join('\n')}`);
    }
  }

  private setupFileWatching(): void {
    watchFile(this.configPath, { interval: 1000 }, () => {
      this.reloadConfig();
    });
    
    if (this.secretsPath) {
      watchFile(this.secretsPath, { interval: 1000 }, () => {
        this.reloadConfig();
      });
    }
  }

  private async reloadConfig(): Promise<void> {
    try {
      await this.loadConfig();
    } catch (error) {
      this.emit('config-reload-error', error);
    }
  }

  private setNestedValue(obj: any, path: string, value: any): void {
    const keys = path.split('_');
    let current = obj;
    
    for (let i = 0; i < keys.length - 1; i++) {
      const key = keys[i];
      if (!(key in current)) {
        current[key] = {};
      }
      current = current[key];
    }
    
    const finalKey = keys[keys.length - 1];
    current[finalKey] = value;
  }

  private parseEnvironmentValue(value: string): any {
    // Try to parse as JSON for complex values
    if (value.startsWith('{') || value.startsWith('[')) {
      try {
        return JSON.parse(value);
      } catch {
        return value;
      }
    }
    
    // Parse boolean strings
    if (value === 'true') return true;
    if (value === 'false') return false;
    
    // Parse numeric strings
    if (!isNaN(Number(value)) && value !== '') {
      return Number(value);
    }
    
    return value;
  }

  private deepMerge(target: any, source: any): any {
    const result = { ...target };
    
    for (const key in source) {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        result[key] = this.deepMerge(result[key] || {}, source[key]);
      } else {
        result[key] = source[key];
      }
    }
    
    return result;
  }

  private getDefaultConfig(): ServerConfiguration {
    return {
      identity: {
        name: 'mcp-server',
        version: '1.0.0',
        description: 'Model Context Protocol Server',
      },
      capabilities: {
        tools: true,
        resources: true,
        prompts: false,
        roots: false,
        sampling: false,
      },
      transport: {
        type: 'stdio' as any,
        options: {},
      },
      security: {
        authentication: {
          enabled: false,
          type: 'none',
          options: {},
        },
        authorization: {
          enabled: false,
          rules: [],
        },
        rateLimit: {
          enabled: true,
          windowMs: 60000,
          maxRequests: 1000,
        },
        cors: {
          enabled: false,
          origins: ['*'],
          methods: ['GET', 'POST'],
          headers: ['Content-Type', 'Authorization'],
          credentials: false,
        },
      },
      performance: {
        timeout: 30000,
        maxConcurrency: 100,
        caching: {
          enabled: false,
          type: 'memory',
          ttl: 3600,
        },
        circuitBreaker: {
          enabled: true,
          failureThreshold: 5,
          resetTimeout: 60000,
          monitoringPeriod: 10000,
        },
      },
      monitoring: {
        metrics: {
          enabled: true,
          interval: 10000,
          retention: 24,
          exporters: ['console'],
        },
        health: {
          enabled: true,
          endpoint: '/health',
          interval: 30000,
          checks: ['memory', 'server'],
        },
        logging: {
          level: 'info',
          format: 'json',
          output: 'console',
        },
      },
    };
  }

  public getConfig(): ServerConfiguration | null {
    return this.config;
  }

  public updateConfig(updates: Partial<ServerConfiguration>): void {
    if (!this.config) {
      throw new Error('Configuration not loaded');
    }
    
    const previousConfig = this.config;
    this.config = this.deepMerge(this.config, updates);
    
    if (this.validateOnLoad && this.config) {
      this.validateConfig(this.config);
    }
    
    this.emit('config-updated', this.config, previousConfig);
  }

  public get<T = any>(path: string, defaultValue?: T): T {
    if (!this.config) {
      throw new Error('Configuration not loaded');
    }
    
    const keys = path.split('.');
    let current: any = this.config;
    
    for (const key of keys) {
      if (current && typeof current === 'object' && key in current) {
        current = current[key];
      } else {
        return defaultValue as T;
      }
    }
    
    return current as T;
  }

  public set(path: string, value: any): void {
    if (!this.config) {
      throw new Error('Configuration not loaded');
    }
    
    const keys = path.split('.');
    let current: any = this.config;
    
    for (let i = 0; i < keys.length - 1; i++) {
      const key = keys[i];
      if (!(key in current) || typeof current[key] !== 'object') {
        current[key] = {};
      }
      current = current[key];
    }
    
    const finalKey = keys[keys.length - 1];
    const previousValue = current[finalKey];
    current[finalKey] = value;
    
    this.emit('config-value-changed', path, value, previousValue);
  }

  public addValidationRule(rule: ValidationRule): void {
    this.validationRules.push(rule);
  }

  public removeValidationRule(field: string): void {
    this.validationRules = this.validationRules.filter(rule => rule.field !== field);
  }

  public exportConfig(): string {
    if (!this.config) {
      throw new Error('Configuration not loaded');
    }
    
    return JSON.stringify(this.config, null, 2);
  }

  public dispose(): void {
    this.removeAllListeners();
    // File watching cleanup is automatic in Node.js
  }
}

// Singleton instance for global configuration management
export const globalConfigManager = new ConfigManager();

// Utility functions for common configuration operations
export const configUtils = {
  // Get configuration manager instance
  getInstance: (options?: ConfigManagerOptions): ConfigManager => {
    return options ? new ConfigManager(options) : globalConfigManager;
  },

  // Load configuration with defaults
  loadWithDefaults: async (configPath?: string): Promise<ServerConfiguration> => {
    const manager = new ConfigManager({ configPath });
    return await manager.loadConfig();
  },

  // Validate configuration object
  validate: (config: ServerConfiguration): void => {
    const manager = new ConfigManager({ validateOnLoad: true });
    manager['validateConfig'](config);
  },

  // Create configuration from environment
  fromEnvironment: (prefix = 'MCP_'): Partial<ServerConfiguration> => {
    const config: any = {};
    
    for (const [key, value] of Object.entries(process.env)) {
      if (key.startsWith(prefix)) {
        const configPath = key.substring(prefix.length).toLowerCase();
        const manager = new ConfigManager();
        manager['setNestedValue'](config, configPath, manager['parseEnvironmentValue'](value || ''));
      }
    }
    
    return config;
  },
};