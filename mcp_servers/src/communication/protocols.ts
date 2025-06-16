/**
 * Standardized Communication Protocols for MCP Servers
 * 
 * This module provides implementations for various communication protocols
 * including JSON-RPC, REST, WebSocket, and gRPC for MCP server communication.
 */

import { EventEmitter } from 'events';
import { WebSocket, WebSocketServer as WSServer } from 'ws';
import express, { Express, Request, Response } from 'express';
import { Server as HTTPServer } from 'http';
import { TransportType, RequestContext, ErrorCode } from '../core/interfaces';
import { MCPError, createErrorResponse } from '../core/utils';
import { createEnhancedLogger, MCPLogger } from '../core/logger';

// ============================================================================
// JSON-RPC Protocol Implementation
// ============================================================================

export interface JSONRPCRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: any;
}

export interface JSONRPCResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: any;
  error?: {
    code: number;
    message: string;
    data?: any;
  };
}

export interface JSONRPCHandler {
  (params: any, context: RequestContext): Promise<any>;
}

export class JSONRPCProcessor extends EventEmitter {
  private handlers: Map<string, JSONRPCHandler> = new Map();
  private logger: MCPLogger;

  constructor(serverName: string) {
    super();
    this.logger = createEnhancedLogger(`${serverName}-jsonrpc`);
  }

  public registerHandler(method: string, handler: JSONRPCHandler): void {
    this.handlers.set(method, handler);
    this.logger.info(`JSON-RPC handler registered: ${method}`);
  }

  public unregisterHandler(method: string): void {
    this.handlers.delete(method);
    this.logger.info(`JSON-RPC handler unregistered: ${method}`);
  }

  public async processRequest(request: JSONRPCRequest, context: RequestContext): Promise<JSONRPCResponse> {
    const startTime = Date.now();
    const requestId = request.id ?? null;

    this.logger.info(`Processing request ${context.requestId}: ${request.method}`);

    try {
      // Validate JSON-RPC format
      if (request.jsonrpc !== '2.0') {
        throw new MCPError(ErrorCode.INVALID_REQUEST, 'Invalid JSON-RPC version');
      }

      if (!request.method || typeof request.method !== 'string') {
        throw new MCPError(ErrorCode.INVALID_REQUEST, 'Method is required and must be a string');
      }

      // Find handler
      const handler = this.handlers.get(request.method);
      if (!handler) {
        throw new MCPError(ErrorCode.METHOD_NOT_FOUND, `Method '${request.method}' not found`);
      }

      // Execute handler
      const result = await handler(request.params || {}, context);
      
      const duration = Date.now() - startTime;
      this.logger.info(`Request ${context.requestId} completed successfully in ${duration}ms`);
      this.emit('request_completed', { method: request.method, duration, success: true });

      return {
        jsonrpc: '2.0',
        id: requestId,
        result,
      };

    } catch (error) {
      const duration = Date.now() - startTime;
      this.logger.error(`Request ${context.requestId} failed in ${duration}ms`);
      this.logger.error(`Error processing request ${requestId}:`, error);
      this.emit('request_completed', { method: request.method, duration, success: false, error });

      const mcpError = error instanceof MCPError ? error : MCPError.fromError(error as Error);
      
      return {
        jsonrpc: '2.0',
        id: requestId,
        error: {
          code: this.getJSONRPCErrorCode(mcpError.code),
          message: mcpError.message,
          data: mcpError.details,
        },
      };
    }
  }

  private getJSONRPCErrorCode(errorCode: string): number {
    const codeMap: Record<string, number> = {
      'INVALID_REQUEST': -32600,
      'METHOD_NOT_FOUND': -32601,
      'INVALID_PARAMS': -32602,
      'INTERNAL_ERROR': -32603,
      'PARSE_ERROR': -32700,
    };
    return codeMap[errorCode] || -32603; // Default to internal error
  }
}

// ============================================================================
// REST Protocol Implementation
// ============================================================================

export interface RESTHandler {
  (req: Request, res: Response, context: RequestContext): Promise<void>;
}

export class RESTServer extends EventEmitter {
  private app: Express;
  private server: HTTPServer | null = null;
  private logger: MCPLogger;
  private port: number;

  constructor(serverName: string, port: number = 3000) {
    super();
    this.app = express();
    this.port = port;
    this.logger = createEnhancedLogger(`${serverName}-rest`);
    
    this.setupMiddleware();
  }

  private setupMiddleware(): void {
    // JSON parsing
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true }));

    // Request logging
    this.app.use((req, res, next) => {
      const requestId = req.headers['x-request-id'] as string || `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const context: RequestContext = {
        requestId,
        timestamp: new Date(),
        metadata: {
          userAgent: req.headers['user-agent'],
          ip: req.ip,
          method: req.method,
          path: req.path,
        },
      };

      (req as any).context = context;
      res.setHeader('X-Request-ID', requestId);

      this.logger.info(`Processing REST request ${requestId}: ${req.method} ${req.path}`);
      next();
    });

    // CORS middleware
    this.app.use((req, res, next) => {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Request-ID');
      
      if (req.method === 'OPTIONS') {
        res.sendStatus(200);
      } else {
        next();
      }
    });
  }

  public registerRoute(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, handler: RESTHandler): void {
    this.app[method.toLowerCase() as 'get' | 'post' | 'put' | 'delete'](path, async (req, res) => {
      const startTime = Date.now();
      const context = (req as any).context as RequestContext;
      
      try {
        await handler(req, res, context);
        
        if (!res.headersSent) {
          const duration = Date.now() - startTime;
          this.logger.info(`REST request ${context.requestId} completed in ${duration}ms`);
          this.emit('request_completed', { method: `${method} ${path}`, duration, success: true });
        }
      } catch (error) {
        const duration = Date.now() - startTime;
        this.logger.error(`REST request ${context.requestId} failed in ${duration}ms`);
        this.logger.error(`Error in REST request ${context.requestId}:`, error);
        this.emit('request_completed', { method: `${method} ${path}`, duration, success: false, error });

        if (!res.headersSent) {
          const errorResponse = createErrorResponse(error as Error, context.requestId);
          res.status(500).json(errorResponse);
        }
      }
    });

    this.logger.info(`REST route registered: ${method} ${path}`);
  }

  public async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = this.app.listen(this.port, () => {
        this.logger.info(`REST server started on port ${this.port}`);
        this.emit('started', { port: this.port });
        resolve();
      });

      this.server.on('error', (error) => {
        this.logger.error(`REST server error on port ${this.port}:`, error);
        reject(error);
      });
    });
  }

  public async stop(): Promise<void> {
    if (this.server) {
      return new Promise((resolve) => {
        this.server!.close(() => {
          this.logger.info('REST server stopped');
          this.emit('stopped');
          resolve();
        });
      });
    }
  }

  public getApp(): Express {
    return this.app;
  }
}

// ============================================================================
// WebSocket Protocol Implementation
// ============================================================================

export interface WebSocketHandler {
  (message: any, ws: WebSocket, context: RequestContext): Promise<void>;
}

export class WebSocketServerProtocol extends EventEmitter {
  private wss: WSServer | null = null;
  private handlers: Map<string, WebSocketHandler> = new Map();
  private logger: MCPLogger;
  private port: number;
  private clients: Set<WebSocket> = new Set();

  constructor(serverName: string, port: number = 8080) {
    super();
    this.port = port;
    this.logger = createEnhancedLogger(`${serverName}-websocket`);
  }

  public registerHandler(messageType: string, handler: WebSocketHandler): void {
    this.handlers.set(messageType, handler);
    this.logger.info(`WebSocket handler registered: ${messageType}`);
  }

  public async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.wss = new WSServer({ port: this.port } as any);

      this.wss.on('connection', (ws) => {
        this.clients.add(ws);
        const clientId = `client_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        
        this.logger.info(`WebSocket client connected: ${clientId}`, { clientCount: this.clients.size });
        this.emit('client_connected', { clientId, clientCount: this.clients.size });

        ws.on('message', async (data) => {
          const startTime = Date.now();
          const requestId = `ws_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
          const context: RequestContext = {
            requestId,
            timestamp: new Date(),
            clientId,
            metadata: { transport: 'websocket' },
          };

          try {
            const message = JSON.parse(data.toString());
            this.logger.info(`Processing WebSocket message ${requestId}: ${message.type || 'unknown'}`);

            const handler = this.handlers.get(message.type);
            if (handler) {
              await handler(message, ws, context);
            } else {
              const errorResponse = {
                type: 'error',
                requestId,
                error: `Unknown message type: ${message.type}`,
              };
              ws.send(JSON.stringify(errorResponse));
            }

            const duration = Date.now() - startTime;
            this.logger.info(`WebSocket message ${requestId} processed in ${duration}ms`);
            this.emit('message_processed', { type: message.type, duration, success: true });

          } catch (error) {
            const duration = Date.now() - startTime;
            this.logger.error(`Error processing WebSocket message ${requestId}:`, error);
            this.emit('message_processed', { duration, success: false, error });

            const errorResponse = {
              type: 'error',
              requestId,
              error: 'Invalid message format',
            };
            ws.send(JSON.stringify(errorResponse));
          }
        });

        ws.on('close', () => {
          this.clients.delete(ws);
          this.logger.info(`WebSocket client disconnected: ${clientId}`, { clientCount: this.clients.size });
          this.emit('client_disconnected', { clientId, clientCount: this.clients.size });
        });

        ws.on('error', (error) => {
          this.logger.error(`WebSocket client error for ${clientId}:`, error);
          this.emit('client_error', { clientId, error });
        });
      });

      this.wss.on('listening', () => {
        this.logger.info(`WebSocket server started on port ${this.port}`);
        this.emit('started', { port: this.port });
        resolve();
      });

      this.wss.on('error', (error) => {
        this.logger.error(`WebSocket server error on port ${this.port}:`, error);
        reject(error);
      });
    });
  }

  public async stop(): Promise<void> {
    if (this.wss) {
      // Close all client connections
      for (const client of this.clients) {
        client.close();
      }
      this.clients.clear();

      return new Promise((resolve) => {
        this.wss!.close(() => {
          this.logger.info('WebSocket server stopped');
          this.emit('stopped');
          resolve();
        });
      });
    }
  }

  public broadcast(message: any): void {
    const data = JSON.stringify(message);
    for (const client of this.clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(data);
      }
    }
    this.logger.info('Message broadcasted to clients', { clientCount: this.clients.size });
  }

  public getClientCount(): number {
    return this.clients.size;
  }
}

// ============================================================================
// Protocol Factory and Manager
// ============================================================================

export interface ProtocolOptions {
  type: TransportType;
  port?: number;
  options?: Record<string, any>;
}

export class ProtocolManager extends EventEmitter {
  private protocols: Map<TransportType, any> = new Map();
  private logger: MCPLogger;

  constructor(serverName: string) {
    super();
    this.logger = createEnhancedLogger(`${serverName}-protocol-manager`);
  }

  public async createProtocol(options: ProtocolOptions): Promise<any> {
    const { type, port } = options;

    switch (type) {
      case TransportType.HTTP:
        const restServer = new RESTServer(this.logger.bindings().server as string, port);
        this.protocols.set(type, restServer);
        return restServer;

      case TransportType.WEBSOCKET:
        const wsServer = new WebSocketServerProtocol(this.logger.bindings().server as string, port);
        this.protocols.set(type, wsServer);
        return wsServer;

      case TransportType.STDIO:
        // STDIO doesn't need a server instance, it's handled by the base server
        return null;

      case TransportType.GRPC:
        // gRPC implementation would go here
        throw new Error('gRPC protocol not yet implemented');

      default:
        throw new Error(`Unsupported protocol type: ${type}`);
    }
  }

  public getProtocol(type: TransportType): any {
    return this.protocols.get(type);
  }

  public async startAll(): Promise<void> {
    const startPromises = [];
    for (const [, protocol] of this.protocols) {
      if (protocol && typeof protocol.start === 'function') {
        startPromises.push(protocol.start());
      }
    }
    await Promise.all(startPromises);
    this.logger.info('All protocols started');
  }

  public async stopAll(): Promise<void> {
    const stopPromises = [];
    for (const [, protocol] of this.protocols) {
      if (protocol && typeof protocol.stop === 'function') {
        stopPromises.push(protocol.stop());
      }
    }
    await Promise.all(stopPromises);
    this.logger.info('All protocols stopped');
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

export function createJSONRPCRequest(method: string, params?: any, id?: string | number): JSONRPCRequest {
  return {
    jsonrpc: '2.0',
    method,
    params,
    id: id ?? `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
  };
}

export function isJSONRPCRequest(obj: any): obj is JSONRPCRequest {
  return obj && obj.jsonrpc === '2.0' && typeof obj.method === 'string';
}

export function isJSONRPCResponse(obj: any): obj is JSONRPCResponse {
  return obj && obj.jsonrpc === '2.0' && ('result' in obj || 'error' in obj);
}