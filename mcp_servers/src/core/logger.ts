import pino, { Logger } from 'pino';
import { config } from './config';
import { LoggingConfig } from './interfaces';

// Enhanced logging configuration
const loggingConfig: LoggingConfig = {
  level: (config.server.logLevel as any) || 'info',
  format: 'json',
  output: 'console',
};

// Create base logger with enhanced configuration
export const logger = pino({
  level: loggingConfig.level,
  base: {
    pid: process.pid,
    hostname: require('os').hostname(),
    service: 'mcp-server',
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  formatters: {
    level: (label) => ({ level: label }),
    log: (object) => ({
      ...object,
      timestamp: new Date().toISOString(),
    }),
  },
  transport: process.env.NODE_ENV === 'development' ? {
    target: 'pino-pretty',
    options: {
      colorize: true,
      translateTime: 'HH:MM:ss Z',
      ignore: 'pid,hostname',
      messageFormat: '{server} [{level}]: {msg}',
    },
  } : undefined,
});

// Enhanced server logger with standardized metadata
export function createServerLogger(serverName: string, metadata?: Record<string, any>): Logger {
  return logger.child({ 
    server: serverName,
    ...metadata 
  });
}

// Structured logging utilities
export const logUtils = {
  // Request logging
  logRequest: (logger: Logger, requestId: string, method: string, params?: any) => {
    logger.info({
      requestId,
      method,
      params: params ? JSON.stringify(params) : undefined,
      type: 'request_start',
    }, `Request started: ${method}`);
  },

  logResponse: (logger: Logger, requestId: string, method: string, duration: number, success: boolean) => {
    logger.info({
      requestId,
      method,
      duration,
      success,
      type: 'request_end',
    }, `Request completed: ${method} (${duration}ms)`);
  },

  // Error logging
  logError: (logger: Logger, error: Error, context?: Record<string, any>) => {
    logger.error({
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack,
      },
      ...context,
      type: 'error',
    }, `Error occurred: ${error.message}`);
  },

  // Performance logging
  logPerformance: (logger: Logger, operation: string, duration: number, metadata?: Record<string, any>) => {
    const level = duration > 5000 ? 'warn' : duration > 1000 ? 'info' : 'debug';
    logger[level]({
      operation,
      duration,
      ...metadata,
      type: 'performance',
    }, `Operation completed: ${operation} (${duration}ms)`);
  },

  // Security logging
  logSecurityEvent: (logger: Logger, event: string, details: Record<string, any>) => {
    logger.warn({
      event,
      ...details,
      type: 'security',
      timestamp: new Date().toISOString(),
    }, `Security event: ${event}`);
  },

  // Health check logging
  logHealthCheck: (logger: Logger, checkName: string, status: string, duration: number, message?: string) => {
    const level = status === 'fail' ? 'error' : status === 'warn' ? 'warn' : 'debug';
    logger[level]({
      checkName,
      status,
      duration,
      message,
      type: 'health_check',
    }, `Health check: ${checkName} - ${status}`);
  },

  // Tool execution logging
  logToolExecution: (logger: Logger, toolName: string, args: any, duration: number, success: boolean, result?: any) => {
    logger.info({
      toolName,
      args: JSON.stringify(args),
      duration,
      success,
      resultSize: result ? JSON.stringify(result).length : 0,
      type: 'tool_execution',
    }, `Tool executed: ${toolName} - ${success ? 'success' : 'failed'} (${duration}ms)`);
  },

  // Resource access logging
  logResourceAccess: (logger: Logger, uri: string, operation: string, success: boolean, size?: number) => {
    logger.info({
      uri,
      operation,
      success,
      size,
      type: 'resource_access',
    }, `Resource ${operation}: ${uri} - ${success ? 'success' : 'failed'}`);
  },
};

// Log correlation utilities
export class LogCorrelation {
  private static correlationId: string | null = null;

  static setCorrelationId(id: string): void {
    this.correlationId = id;
  }

  static getCorrelationId(): string | null {
    return this.correlationId;
  }

  static withCorrelation<T>(id: string, fn: () => T): T {
    const previousId = this.correlationId;
    this.correlationId = id;
    try {
      return fn();
    } finally {
      this.correlationId = previousId;
    }
  }

  static createLogger(logger: Logger): Logger {
    return logger.child({
      correlationId: this.correlationId,
    });
  }
}

// Export enhanced logger types
export interface MCPLogger extends Logger {
  logRequest: typeof logUtils.logRequest;
  logResponse: typeof logUtils.logResponse;
  logError: typeof logUtils.logError;
  logPerformance: typeof logUtils.logPerformance;
  logSecurityEvent: typeof logUtils.logSecurityEvent;
  logHealthCheck: typeof logUtils.logHealthCheck;
  logToolExecution: typeof logUtils.logToolExecution;
  logResourceAccess: typeof logUtils.logResourceAccess;
}

export function createEnhancedLogger(serverName: string, metadata?: Record<string, any>): MCPLogger {
  const baseLogger = createServerLogger(serverName, metadata);
  
  return Object.assign(baseLogger, {
    logRequest: (logger: Logger, requestId: string, method: string, params?: any) => 
      logUtils.logRequest(logger, requestId, method, params),
    logResponse: (logger: Logger, requestId: string, method: string, duration: number, success: boolean) => 
      logUtils.logResponse(logger, requestId, method, duration, success),
    logError: (logger: Logger, error: Error, context?: Record<string, any>) => 
      logUtils.logError(logger, error, context),
    logPerformance: (logger: Logger, operation: string, duration: number, metadata?: Record<string, any>) => 
      logUtils.logPerformance(logger, operation, duration, metadata),
    logSecurityEvent: (logger: Logger, event: string, details: Record<string, any>) => 
      logUtils.logSecurityEvent(logger, event, details),
    logHealthCheck: (logger: Logger, checkName: string, status: string, duration: number, message?: string) => 
      logUtils.logHealthCheck(logger, checkName, status, duration, message),
    logToolExecution: (logger: Logger, toolName: string, args: any, duration: number, success: boolean, result?: any) => 
      logUtils.logToolExecution(logger, toolName, args, duration, success, result),
    logResourceAccess: (logger: Logger, uri: string, operation: string, success: boolean, size?: number) => 
      logUtils.logResourceAccess(logger, uri, operation, success, size),
  });
}