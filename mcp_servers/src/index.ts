import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { config, validateConfig } from './core/config';
import { logger } from './core/logger';
import { registry } from './registry/server-registry';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';

// Validate configuration on startup
try {
  validateConfig();
} catch (error: any) {
  logger.error({ error }, 'Configuration validation failed');
  process.exit(1);
}

// Create Express app
const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

// Middleware
app.use(helmet());
app.use(cors({ origin: config.security.corsOrigins }));
app.use(express.json());

// Rate limiting
if (config.rateLimit.enabled) {
  const limiter = rateLimit({
    windowMs: config.rateLimit.windowMs,
    max: config.rateLimit.maxRequests,
    message: 'Too many requests from this IP',
  });
  app.use('/api/', limiter);
}

// Health check endpoint
app.get('/health', (_req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
  });
});

// Server registry endpoints
app.get('/api/servers', async (_req, res) => {
  try {
    const servers = registry.getAllServers();
    res.json({ servers });
  } catch (error: any) {
    logger.error({ error }, 'Failed to get servers');
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/servers/:name', async (req, res) => {
  try {
    const server = registry.getServer(req.params.name);
    if (!server) {
      res.status(404).json({ error: 'Server not found' });
      return;
    }
    res.json({ server });
  } catch (error: any) {
    logger.error({ error }, 'Failed to get server');
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/servers/:name/start', async (req, res) => {
  try {
    await registry.startServer(req.params.name);
    res.json({ message: 'Server started successfully' });
  } catch (error: any) {
    logger.error({ error }, 'Failed to start server');
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/servers/:name/stop', async (req, res) => {
  try {
    await registry.stopServer(req.params.name);
    res.json({ message: 'Server stopped successfully' });
  } catch (error: any) {
    logger.error({ error }, 'Failed to stop server');
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/servers/:name/restart', async (req, res) => {
  try {
    await registry.restartServer(req.params.name);
    res.json({ message: 'Server restarted successfully' });
  } catch (error: any) {
    logger.error({ error }, 'Failed to restart server');
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/status', async (_req, res) => {
  try {
    const status = await registry.getServerStatus();
    res.json(status);
  } catch (error: any) {
    logger.error({ error }, 'Failed to get status');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// WebSocket connections for real-time updates
wss.on('connection', (ws) => {
  logger.info('WebSocket client connected');
  
  // Send initial status
  registry.getServerStatus().then(status => {
    ws.send(JSON.stringify({ type: 'status', data: status }));
  });
  
  // Subscribe to registry events
  const handlers = {
    'server:registered': (name: string) => {
      ws.send(JSON.stringify({ type: 'server:registered', server: name }));
    },
    'server:starting': (name: string) => {
      ws.send(JSON.stringify({ type: 'server:starting', server: name }));
    },
    'server:started': (name: string) => {
      ws.send(JSON.stringify({ type: 'server:started', server: name }));
    },
    'server:stopping': (name: string) => {
      ws.send(JSON.stringify({ type: 'server:stopping', server: name }));
    },
    'server:stopped': (name: string) => {
      ws.send(JSON.stringify({ type: 'server:stopped', server: name }));
    },
    'server:error': (name: string, error: Error) => {
      ws.send(JSON.stringify({ type: 'server:error', server: name, error: error.message }));
    },
  };
  
  Object.entries(handlers).forEach(([event, handler]) => {
    registry.on(event, handler);
  });
  
  ws.on('close', () => {
    logger.info('WebSocket client disconnected');
    // Unsubscribe from events
    Object.entries(handlers).forEach(([event, handler]) => {
      registry.removeListener(event, handler);
    });
  });
  
  ws.on('error', (error) => {
    logger.error({ error }, 'WebSocket error');
  });
});

// Error handling
app.use((err: any, _req: any, res: any, _next: any) => {
  logger.error({ error: err }, 'Unhandled error');
  res.status(500).json({ error: 'Internal server error' });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down gracefully');
  
  server.close(() => {
    logger.info('HTTP server closed');
  });
  
  await registry.shutdown();
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received, shutting down gracefully');
  
  server.close(() => {
    logger.info('HTTP server closed');
  });
  
  await registry.shutdown();
  process.exit(0);
});

// Start the server
const PORT = config.server.port;
const HOST = config.server.host;

server.listen(PORT, HOST, () => {
  logger.info(
    { port: PORT, host: HOST },
    'MCP Server Manager is running'
  );
  
  logger.info('Available endpoints:');
  logger.info(`  Health: http://${HOST}:${PORT}/health`);
  logger.info(`  API: http://${HOST}:${PORT}/api/servers`);
  logger.info(`  WebSocket: ws://${HOST}:${PORT}/ws`);
  
  // Start auto-start servers
  logger.info('Starting auto-start servers...');
  registry.startAll().catch(error => {
    logger.error({ error }, 'Failed to start auto-start servers');
  });
});

export { app, server, registry };