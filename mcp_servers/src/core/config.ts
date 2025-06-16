import dotenv from 'dotenv';
import path from 'path';

// Load environment variables
dotenv.config({ path: path.join(__dirname, '../../config/api_keys.env') });

export interface MCPServerConfig {
  // API Keys
  tavily: {
    apiKey: string;
  };
  smithery: {
    apiKey: string;
  };
  brave: {
    apiKey: string;
  };
  
  // Server Configuration
  server: {
    port: number;
    host: string;
    authEnabled: boolean;
    logLevel: string;
  };
  
  // Rate Limiting
  rateLimit: {
    enabled: boolean;
    windowMs: number;
    maxRequests: number;
  };
  
  // Redis Configuration
  redis: {
    url: string;
    enabled: boolean;
  };
  
  // Security
  security: {
    jwtSecret: string;
    corsOrigins: string[];
  };
}

export const config: MCPServerConfig = {
  // API Keys
  tavily: {
    apiKey: process.env.TAVILY_API_KEY || '',
  },
  smithery: {
    apiKey: process.env.SMITHERY_API_KEY || '',
  },
  brave: {
    apiKey: process.env.BRAVE_API_KEY || '',
  },
  
  // Server Configuration
  server: {
    port: parseInt(process.env.MCP_SERVER_PORT || '3000', 10),
    host: process.env.MCP_SERVER_HOST || '0.0.0.0',
    authEnabled: process.env.MCP_AUTH_ENABLED === 'true',
    logLevel: process.env.MCP_LOG_LEVEL || 'info',
  },
  
  // Rate Limiting
  rateLimit: {
    enabled: process.env.MCP_RATE_LIMIT_ENABLED === 'true',
    windowMs: parseInt(process.env.MCP_RATE_LIMIT_WINDOW_MS || '60000', 10),
    maxRequests: parseInt(process.env.MCP_RATE_LIMIT_MAX_REQUESTS || '100', 10),
  },
  
  // Redis Configuration
  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    enabled: process.env.REDIS_ENABLED === 'true',
  },
  
  // Security
  security: {
    jwtSecret: process.env.JWT_SECRET || 'mcp-server-jwt-secret-change-in-production',
    corsOrigins: (process.env.CORS_ORIGINS || 'http://localhost:3000').split(','),
  },
};

// Validate required API keys
export function validateConfig(): void {
  const errors: string[] = [];
  
  if (!config.tavily.apiKey) {
    errors.push('TAVILY_API_KEY is required');
  }
  
  if (!config.smithery.apiKey) {
    errors.push('SMITHERY_API_KEY is required');
  }
  
  if (!config.brave.apiKey) {
    errors.push('BRAVE_API_KEY is required');
  }
  
  if (errors.length > 0) {
    throw new Error(`Configuration validation failed:\\n${errors.join('\\n')}`);
  }
}