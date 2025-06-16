/**
 * Shared Utility Functions for MCP Server Architecture
 * 
 * Common utilities that can be used across all server implementations
 * for consistent behavior and reduced code duplication.
 */

import { ErrorCode, ErrorInfo, HealthCheck, CheckStatus, ResponseWrapper } from './interfaces';

// ============================================================================
// Error Utilities
// ============================================================================

export class MCPError extends Error {
  constructor(
    public code: ErrorCode,
    message: string,
    public details?: Record<string, any>,
    public retryable: boolean = false,
    public retryAfter?: number
  ) {
    super(message);
    this.name = 'MCPError';
  }

  toErrorInfo(): ErrorInfo {
    return {
      code: this.code,
      message: this.message,
      details: this.details,
      stack: this.stack,
      retryable: this.retryable,
      retryAfter: this.retryAfter,
    };
  }

  static fromError(error: Error, code: ErrorCode = ErrorCode.INTERNAL_ERROR): MCPError {
    if (error instanceof MCPError) {
      return error;
    }
    return new MCPError(code, error.message, { originalError: error.constructor.name });
  }
}

export function createErrorResponse<T = any>(
  error: Error | MCPError,
  requestId: string
): ResponseWrapper<T> {
  const mcpError = error instanceof MCPError ? error : MCPError.fromError(error);
  
  return {
    success: false,
    error: mcpError.toErrorInfo(),
    requestId,
    timestamp: new Date(),
  };
}

export function createSuccessResponse<T>(
  data: T,
  requestId: string,
  metadata?: Record<string, any>
): ResponseWrapper<T> {
  return {
    success: true,
    data,
    requestId,
    timestamp: new Date(),
    metadata,
  };
}

// ============================================================================
// Validation Utilities
// ============================================================================

export interface ValidationRule<T = any> {
  field: string;
  validate: (value: T) => boolean | string;
  required?: boolean;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

export function validateObject<T extends Record<string, any>>(
  obj: T,
  rules: ValidationRule[]
): ValidationResult {
  const errors: string[] = [];

  for (const rule of rules) {
    const value = obj[rule.field];
    
    // Check required fields
    if (rule.required && (value === undefined || value === null)) {
      errors.push(`Field '${rule.field}' is required`);
      continue;
    }
    
    // Skip validation for optional undefined fields
    if (!rule.required && (value === undefined || value === null)) {
      continue;
    }
    
    // Run validation
    const result = rule.validate(value);
    if (result !== true) {
      const message = typeof result === 'string' ? result : `Field '${rule.field}' is invalid`;
      errors.push(message);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

export const commonValidators = {
  string: (value: any) => typeof value === 'string' || 'Must be a string',
  number: (value: any) => typeof value === 'number' || 'Must be a number',
  boolean: (value: any) => typeof value === 'boolean' || 'Must be a boolean',
  array: (value: any) => Array.isArray(value) || 'Must be an array',
  object: (value: any) => typeof value === 'object' && value !== null || 'Must be an object',
  email: (value: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) || 'Must be a valid email',
  url: (value: string) => {
    try {
      new URL(value);
      return true;
    } catch {
      return 'Must be a valid URL';
    }
  },
  minLength: (min: number) => (value: string) => 
    value.length >= min || `Must be at least ${min} characters`,
  maxLength: (max: number) => (value: string) => 
    value.length <= max || `Must be no more than ${max} characters`,
  range: (min: number, max: number) => (value: number) => 
    (value >= min && value <= max) || `Must be between ${min} and ${max}`,
};

// ============================================================================
// Rate Limiting Utilities
// ============================================================================

export class RateLimiter {
  private requests: Map<string, number[]> = new Map();

  constructor(
    private windowMs: number,
    private maxRequests: number
  ) {}

  checkLimit(key: string): { allowed: boolean; retryAfter?: number } {
    const now = Date.now();
    const requests = this.requests.get(key) || [];
    
    // Remove old requests outside the window
    const validRequests = requests.filter(time => now - time < this.windowMs);
    
    if (validRequests.length >= this.maxRequests) {
      const oldestRequest = Math.min(...validRequests);
      const retryAfter = Math.ceil((oldestRequest + this.windowMs - now) / 1000);
      return { allowed: false, retryAfter };
    }
    
    // Add current request
    validRequests.push(now);
    this.requests.set(key, validRequests);
    
    return { allowed: true };
  }

  reset(key?: string): void {
    if (key) {
      this.requests.delete(key);
    } else {
      this.requests.clear();
    }
  }
}

// ============================================================================
// Circuit Breaker Utilities
// ============================================================================

export enum CircuitState {
  CLOSED = 'closed',
  OPEN = 'open',
  HALF_OPEN = 'half_open'
}

export class CircuitBreaker {
  private failures = 0;
  private lastFailureTime = 0;
  private state = CircuitState.CLOSED;

  constructor(
    private failureThreshold: number,
    private resetTimeoutMs: number
  ) {}

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (this.state === CircuitState.OPEN) {
      if (Date.now() - this.lastFailureTime >= this.resetTimeoutMs) {
        this.state = CircuitState.HALF_OPEN;
      } else {
        throw new MCPError(
          ErrorCode.SERVER_UNAVAILABLE,
          'Circuit breaker is open',
          { state: this.state },
          true,
          Math.ceil((this.lastFailureTime + this.resetTimeoutMs - Date.now()) / 1000)
        );
      }
    }

    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    this.failures = 0;
    this.state = CircuitState.CLOSED;
  }

  private onFailure(): void {
    this.failures++;
    this.lastFailureTime = Date.now();
    
    if (this.failures >= this.failureThreshold) {
      this.state = CircuitState.OPEN;
    }
  }

  getState(): CircuitState {
    return this.state;
  }
}

// ============================================================================
// Retry Utilities
// ============================================================================

export interface RetryOptions {
  maxAttempts: number;
  delayMs: number;
  exponentialBackoff: boolean;
  jitter: boolean;
  retryCondition?: (error: Error) => boolean;
}

export async function withRetry<T>(
  operation: () => Promise<T>,
  options: Partial<RetryOptions> = {}
): Promise<T> {
  const {
    maxAttempts = 3,
    delayMs = 1000,
    exponentialBackoff = true,
    jitter = true,
    retryCondition = (error) => !(error instanceof MCPError) || error.retryable
  } = options;

  let lastError: Error;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error as Error;
      
      if (attempt === maxAttempts || !retryCondition(lastError)) {
        throw lastError;
      }
      
      let delay = delayMs;
      if (exponentialBackoff) {
        delay *= Math.pow(2, attempt - 1);
      }
      if (jitter) {
        delay += Math.random() * delay * 0.1; // Add 10% jitter
      }
      
      await sleep(delay);
    }
  }

  throw lastError!;
}

// ============================================================================
// Async Utilities
// ============================================================================

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export async function timeout<T>(
  promise: Promise<T>,
  ms: number,
  errorMessage = 'Operation timed out'
): Promise<T> {
  const timeoutPromise = new Promise<never>((_, reject) => {
    setTimeout(() => reject(new MCPError(ErrorCode.TOOL_TIMEOUT, errorMessage)), ms);
  });

  return Promise.race([promise, timeoutPromise]);
}

export function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeoutId: NodeJS.Timeout;
  
  return (...args: Parameters<T>) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => func(...args), wait);
  };
}

export function throttle<T extends (...args: any[]) => any>(
  func: T,
  limit: number
): (...args: Parameters<T>) => void {
  let inThrottle: boolean;
  
  return (...args: Parameters<T>) => {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

// ============================================================================
// Health Check Utilities
// ============================================================================

export function createHealthCheck(
  name: string,
  checkFn: () => Promise<boolean> | boolean,
  options: {
    timeout?: number;
    warningThreshold?: number;
    errorMessage?: string;
  } = {}
): () => Promise<HealthCheck> {
  return async () => {
    const start = Date.now();
    
    try {
      const timeoutMs = options.timeout || 5000;
      const result = await timeout(
        Promise.resolve(checkFn()),
        timeoutMs,
        `Health check '${name}' timed out`
      );
      
      const duration = Date.now() - start;
      const warningThreshold = options.warningThreshold || 1000;
      
      return {
        name,
        status: result ? 
          (duration > warningThreshold ? CheckStatus.WARN : CheckStatus.PASS) : 
          CheckStatus.FAIL,
        message: result ? 
          (duration > warningThreshold ? `Slow response: ${duration}ms` : 'OK') :
          options.errorMessage || 'Check failed',
        duration,
      };
    } catch (error) {
      return {
        name,
        status: CheckStatus.FAIL,
        message: error instanceof Error ? error.message : 'Check failed',
        duration: Date.now() - start,
      };
    }
  };
}

// ============================================================================
// Configuration Utilities
// ============================================================================

export function loadConfig<T>(
  defaultConfig: T,
  envPrefix: string = 'MCP_'
): T {
  const config = { ...defaultConfig };
  
  function setNestedValue(obj: any, path: string, value: any): void {
    const keys = path.split('_');
    let current = obj;
    
    for (let i = 0; i < keys.length - 1; i++) {
      const key = keys[i].toLowerCase();
      if (!(key in current)) {
        current[key] = {};
      }
      current = current[key];
    }
    
    const finalKey = keys[keys.length - 1].toLowerCase();
    current[finalKey] = value;
  }
  
  // Override with environment variables
  for (const [key, value] of Object.entries(process.env)) {
    if (key.startsWith(envPrefix)) {
      const configPath = key.substring(envPrefix.length);
      let parsedValue: any = value;
      
      // Try to parse as JSON for complex values
      if (value?.startsWith('{') || value?.startsWith('[')) {
        try {
          parsedValue = JSON.parse(value);
        } catch {
          // Keep as string if JSON parsing fails
        }
      }
      // Parse boolean strings
      else if (value === 'true' || value === 'false') {
        parsedValue = value === 'true';
      }
      // Parse numeric strings
      else if (!isNaN(Number(value)) && value !== '') {
        parsedValue = Number(value);
      }
      
      setNestedValue(config, configPath, parsedValue);
    }
  }
  
  return config;
}

// ============================================================================
// Logging Utilities
// ============================================================================

export function createStructuredLogger(serverName: string) {
  return {
    debug: (message: string, meta?: Record<string, any>) => 
      console.debug(JSON.stringify({ level: 'debug', server: serverName, message, ...meta, timestamp: new Date().toISOString() })),
    
    info: (message: string, meta?: Record<string, any>) => 
      console.info(JSON.stringify({ level: 'info', server: serverName, message, ...meta, timestamp: new Date().toISOString() })),
    
    warn: (message: string, meta?: Record<string, any>) => 
      console.warn(JSON.stringify({ level: 'warn', server: serverName, message, ...meta, timestamp: new Date().toISOString() })),
    
    error: (message: string, meta?: Record<string, any>) => 
      console.error(JSON.stringify({ level: 'error', server: serverName, message, ...meta, timestamp: new Date().toISOString() })),
  };
}