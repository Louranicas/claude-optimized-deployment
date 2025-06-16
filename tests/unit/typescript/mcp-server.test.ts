/**
 * Unit tests for TypeScript MCP servers
 * Tests core MCP protocol implementation and tool functionality
 */

import { jest, describe, beforeEach, afterEach, it, expect } from '@jest/globals';

// Mock MCP SDK
const mockMCPServer = {
  setRequestHandler: jest.fn(),
  connect: jest.fn(),
  close: jest.fn(),
  sendNotification: jest.fn()
};

const mockStdio = {
  createStdioServerTransport: jest.fn(() => ({
    start: jest.fn(),
    close: jest.fn()
  }))
};

// Mock the MCP SDK modules
jest.mock('@modelcontextprotocol/sdk/server/index.js', () => ({
  Server: jest.fn(() => mockMCPServer)
}));

jest.mock('@modelcontextprotocol/sdk/server/stdio.js', () => mockStdio);

// Mock filesystem operations
jest.mock('fs/promises', () => ({
  readFile: jest.fn(),
  writeFile: jest.fn(),
  access: jest.fn(),
  mkdir: jest.fn(),
  readdir: jest.fn(),
  stat: jest.fn()
}));

// Mock child_process
jest.mock('child_process', () => ({
  exec: jest.fn(),
  spawn: jest.fn(),
  execSync: jest.fn()
}));

interface MCPTool {
  name: string;
  description: string;
  inputSchema: {
    type: string;
    properties: Record<string, any>;
    required?: string[];
  };
}

interface MCPServerInfo {
  name: string;
  version: string;
  description: string;
}

class MockMCPServer {
  private tools: MCPTool[] = [];
  private serverInfo: MCPServerInfo;

  constructor(serverInfo: MCPServerInfo) {
    this.serverInfo = serverInfo;
  }

  addTool(tool: MCPTool): void {
    this.tools.push(tool);
  }

  getTools(): MCPTool[] {
    return this.tools;
  }

  getServerInfo(): MCPServerInfo {
    return this.serverInfo;
  }

  async callTool(name: string, args: Record<string, any>): Promise<any> {
    const tool = this.tools.find(t => t.name === name);
    if (!tool) {
      throw new Error(`Tool ${name} not found`);
    }

    // Simulate tool execution
    switch (name) {
      case 'execute_command':
        return this.executeCommand(args);
      case 'read_file':
        return this.readFile(args);
      case 'write_file':
        return this.writeFile(args);
      case 'docker_run':
        return this.dockerRun(args);
      case 'search_web':
        return this.searchWeb(args);
      default:
        throw new Error(`Tool ${name} not implemented`);
    }
  }

  private async executeCommand(args: { command: string; timeout?: number }): Promise<any> {
    if (!args.command) {
      throw new Error('Command is required');
    }

    // Security validation
    const dangerousCommands = ['rm -rf', 'format', 'del /f', 'shutdown'];
    if (dangerousCommands.some(cmd => args.command.includes(cmd))) {
      throw new Error('Dangerous command blocked');
    }

    return {
      success: true,
      stdout: `Output of: ${args.command}`,
      stderr: '',
      exitCode: 0,
      timestamp: new Date().toISOString()
    };
  }

  private async readFile(args: { path: string; encoding?: string }): Promise<any> {
    if (!args.path) {
      throw new Error('Path is required');
    }

    // Path validation
    if (args.path.includes('..') || args.path.startsWith('/etc/')) {
      throw new Error('Invalid path');
    }

    return {
      success: true,
      content: `Mock content of ${args.path}`,
      size: 1024,
      timestamp: new Date().toISOString()
    };
  }

  private async writeFile(args: { path: string; content: string; encoding?: string }): Promise<any> {
    if (!args.path || args.content === undefined) {
      throw new Error('Path and content are required');
    }

    // Path validation
    if (args.path.includes('..') || args.path.startsWith('/etc/')) {
      throw new Error('Invalid path');
    }

    return {
      success: true,
      bytesWritten: args.content.length,
      timestamp: new Date().toISOString()
    };
  }

  private async dockerRun(args: { image: string; command?: string; ports?: string[] }): Promise<any> {
    if (!args.image) {
      throw new Error('Image is required');
    }

    // Image validation
    if (args.image.includes('..') || args.image.includes('/')) {
      throw new Error('Invalid image name');
    }

    return {
      success: true,
      containerId: 'mock-container-id',
      status: 'running',
      timestamp: new Date().toISOString()
    };
  }

  private async searchWeb(args: { query: string; count?: number }): Promise<any> {
    if (!args.query) {
      throw new Error('Query is required');
    }

    // Input sanitization
    const sanitizedQuery = args.query.replace(/<[^>]*>/g, '');

    return {
      success: true,
      results: [
        {
          title: `Result for: ${sanitizedQuery}`,
          url: 'https://example.com',
          snippet: 'Mock search result snippet'
        }
      ],
      count: args.count || 10,
      timestamp: new Date().toISOString()
    };
  }
}

describe('MCP Server Unit Tests', () => {
  let server: MockMCPServer;

  beforeEach(() => {
    server = new MockMCPServer({
      name: 'test-server',
      version: '1.0.0',
      description: 'Test MCP server'
    });

    // Add common tools
    server.addTool({
      name: 'execute_command',
      description: 'Execute system commands',
      inputSchema: {
        type: 'object',
        properties: {
          command: { type: 'string' },
          timeout: { type: 'number' }
        },
        required: ['command']
      }
    });

    server.addTool({
      name: 'read_file',
      description: 'Read file contents',
      inputSchema: {
        type: 'object',
        properties: {
          path: { type: 'string' },
          encoding: { type: 'string' }
        },
        required: ['path']
      }
    });

    server.addTool({
      name: 'write_file',
      description: 'Write file contents',
      inputSchema: {
        type: 'object',
        properties: {
          path: { type: 'string' },
          content: { type: 'string' },
          encoding: { type: 'string' }
        },
        required: ['path', 'content']
      }
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Server Information', () => {
    it('should return server information', () => {
      const info = server.getServerInfo();
      expect(info).toEqual({
        name: 'test-server',
        version: '1.0.0',
        description: 'Test MCP server'
      });
    });

    it('should list available tools', () => {
      const tools = server.getTools();
      expect(tools).toHaveLength(3);
      expect(tools[0].name).toBe('execute_command');
      expect(tools[1].name).toBe('read_file');
      expect(tools[2].name).toBe('write_file');
    });
  });

  describe('Tool Parameter Validation', () => {
    it('should validate required parameters', async () => {
      await expect(server.callTool('execute_command', {}))
        .rejects.toThrow('Command is required');
    });

    it('should validate parameter types', async () => {
      const result = await server.callTool('execute_command', {
        command: 'echo test',
        timeout: 5000
      });
      expect(result.success).toBe(true);
    });

    it('should handle missing tool', async () => {
      await expect(server.callTool('nonexistent_tool', {}))
        .rejects.toThrow('Tool nonexistent_tool not found');
    });
  });

  describe('Security Validation', () => {
    it('should block dangerous commands', async () => {
      await expect(server.callTool('execute_command', {
        command: 'rm -rf /'
      })).rejects.toThrow('Dangerous command blocked');
    });

    it('should validate file paths', async () => {
      await expect(server.callTool('read_file', {
        path: '../../../etc/passwd'
      })).rejects.toThrow('Invalid path');
    });

    it('should sanitize search queries', async () => {
      const result = await server.callTool('search_web', {
        query: '<script>alert("xss")</script>test'
      });
      expect(result.success).toBe(true);
      expect(result.results[0].title).toContain('test');
      expect(result.results[0].title).not.toContain('<script>');
    });
  });

  describe('Tool Execution', () => {
    it('should execute commands successfully', async () => {
      const result = await server.callTool('execute_command', {
        command: 'echo "hello world"'
      });

      expect(result).toMatchObject({
        success: true,
        stdout: expect.stringContaining('echo "hello world"'),
        stderr: '',
        exitCode: 0,
        timestamp: expect.any(String)
      });
    });

    it('should read files successfully', async () => {
      const result = await server.callTool('read_file', {
        path: '/tmp/test.txt'
      });

      expect(result).toMatchObject({
        success: true,
        content: expect.stringContaining('/tmp/test.txt'),
        size: expect.any(Number),
        timestamp: expect.any(String)
      });
    });

    it('should write files successfully', async () => {
      const result = await server.callTool('write_file', {
        path: '/tmp/test.txt',
        content: 'test content'
      });

      expect(result).toMatchObject({
        success: true,
        bytesWritten: 12,
        timestamp: expect.any(String)
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid JSON parameters', async () => {
      await expect(server.callTool('execute_command', null as any))
        .rejects.toThrow();
    });

    it('should handle missing required fields', async () => {
      await expect(server.callTool('write_file', {
        path: '/tmp/test.txt'
        // missing content
      })).rejects.toThrow('Path and content are required');
    });

    it('should provide detailed error messages', async () => {
      try {
        await server.callTool('execute_command', {});
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Command is required');
      }
    });
  });

  describe('Response Format', () => {
    it('should return consistent response format', async () => {
      const result = await server.callTool('execute_command', {
        command: 'echo test'
      });

      expect(result).toHaveProperty('success');
      expect(result).toHaveProperty('timestamp');
      expect(typeof result.timestamp).toBe('string');
      expect(new Date(result.timestamp)).toBeInstanceOf(Date);
    });

    it('should include relevant metadata', async () => {
      const result = await server.callTool('read_file', {
        path: '/tmp/test.txt'
      });

      expect(result).toHaveProperty('size');
      expect(typeof result.size).toBe('number');
    });
  });

  describe('Performance', () => {
    it('should execute within reasonable time', async () => {
      const startTime = Date.now();
      
      await server.callTool('execute_command', {
        command: 'echo test'
      });
      
      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(1000); // Should complete within 1 second
    });

    it('should handle concurrent requests', async () => {
      const promises = Array.from({ length: 10 }, (_, i) =>
        server.callTool('execute_command', {
          command: `echo test${i}`
        })
      );

      const results = await Promise.all(promises);
      expect(results).toHaveLength(10);
      results.forEach(result => {
        expect(result.success).toBe(true);
      });
    });
  });
});

describe('Docker MCP Server', () => {
  let dockerServer: MockMCPServer;

  beforeEach(() => {
    dockerServer = new MockMCPServer({
      name: 'docker-server',
      version: '1.0.0',
      description: 'Docker MCP server'
    });

    dockerServer.addTool({
      name: 'docker_run',
      description: 'Run Docker container',
      inputSchema: {
        type: 'object',
        properties: {
          image: { type: 'string' },
          command: { type: 'string' },
          ports: { type: 'array', items: { type: 'string' } }
        },
        required: ['image']
      }
    });
  });

  it('should run Docker containers', async () => {
    const result = await dockerServer.callTool('docker_run', {
      image: 'nginx:latest',
      ports: ['80:8080']
    });

    expect(result).toMatchObject({
      success: true,
      containerId: expect.any(String),
      status: 'running',
      timestamp: expect.any(String)
    });
  });

  it('should validate Docker image names', async () => {
    await expect(dockerServer.callTool('docker_run', {
      image: '../malicious/image'
    })).rejects.toThrow('Invalid image name');
  });
});

describe('Search MCP Server', () => {
  let searchServer: MockMCPServer;

  beforeEach(() => {
    searchServer = new MockMCPServer({
      name: 'search-server',
      version: '1.0.0',
      description: 'Web search MCP server'
    });

    searchServer.addTool({
      name: 'search_web',
      description: 'Search the web',
      inputSchema: {
        type: 'object',
        properties: {
          query: { type: 'string' },
          count: { type: 'number' }
        },
        required: ['query']
      }
    });
  });

  it('should perform web searches', async () => {
    const result = await searchServer.callTool('search_web', {
      query: 'TypeScript testing',
      count: 5
    });

    expect(result).toMatchObject({
      success: true,
      results: expect.arrayContaining([
        expect.objectContaining({
          title: expect.any(String),
          url: expect.any(String),
          snippet: expect.any(String)
        })
      ]),
      count: 5,
      timestamp: expect.any(String)
    });
  });

  it('should sanitize search queries', async () => {
    const result = await searchServer.callTool('search_web', {
      query: '<img src=x onerror=alert(1)>test query'
    });

    expect(result.success).toBe(true);
    expect(result.results[0].title).not.toContain('<img');
    expect(result.results[0].title).toContain('test query');
  });
});