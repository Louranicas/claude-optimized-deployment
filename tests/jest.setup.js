/**
 * Jest setup file for MCP server testing
 * Configures global test environment and utilities
 */

// Environment configuration
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error'; // Reduce log noise in tests

// Global test timeout
jest.setTimeout(30000);

// Mock implementations for external services
const mockServices = {
  // Mock HTTP requests
  fetch: jest.fn(),
  
  // Mock file system operations
  fs: {
    promises: {
      readFile: jest.fn(),
      writeFile: jest.fn(),
      access: jest.fn(),
      mkdir: jest.fn()
    }
  },
  
  // Mock child process
  child_process: {
    exec: jest.fn(),
    spawn: jest.fn(),
    execSync: jest.fn()
  }
};

// Global test utilities
global.testUtils = {
  // Create test context
  createTestContext: () => ({
    id: `test_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    timestamp: new Date().toISOString(),
    environment: 'test'
  }),
  
  // Wait for async operations
  waitFor: (ms) => new Promise(resolve => setTimeout(resolve, ms)),
  
  // Mock MCP server response
  createMockServerResponse: (data = {}, success = true) => ({
    success,
    data,
    timestamp: new Date().toISOString(),
    requestId: global.testUtils.createTestContext().id
  }),
  
  // Mock MCP tool definition
  createMockTool: (name, description = 'Test tool') => ({
    name,
    description,
    parameters: [
      {
        name: 'input',
        type: 'string',
        description: 'Test input parameter',
        required: true
      }
    ]
  }),
  
  // Mock error response
  createMockError: (message = 'Test error', code = 'TEST_ERROR') => ({
    error: {
      code,
      message,
      timestamp: new Date().toISOString()
    }
  })
};

// Global test data
global.testData = {
  // Sample MCP servers
  servers: {
    desktop: {
      name: 'desktop-commander',
      version: '1.0.0',
      description: 'Desktop command execution',
      tools: ['execute_command', 'read_file', 'write_file']
    },
    docker: {
      name: 'docker',
      version: '1.0.0', 
      description: 'Docker container management',
      tools: ['docker_run', 'docker_build', 'docker_ps']
    },
    security: {
      name: 'security-scanner',
      version: '1.0.0',
      description: 'Security scanning tools',
      tools: ['scan_dependencies', 'check_vulnerabilities']
    }
  },
  
  // Sample test parameters
  parameters: {
    valid: {
      command: 'echo "test"',
      query: 'test search',
      path: '/tmp/test.txt',
      content: 'test content'
    },
    invalid: {
      command: null,
      query: '',
      path: '../../../etc/passwd',
      content: undefined
    },
    malicious: {
      command: 'rm -rf /',
      query: '<script>alert("xss")</script>',
      path: '../../../../etc/passwd',
      content: '<?php system($_GET["cmd"]); ?>'
    }
  }
};

// Console suppression for tests
if (process.env.SUPPRESS_TEST_LOGS !== 'false') {
  global.console = {
    ...console,
    log: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn()
  };
}

// Memory leak detection
beforeEach(() => {
  global.testStartTime = process.hrtime.bigint();
  global.testStartMemory = process.memoryUsage();
});

afterEach(() => {
  const endTime = process.hrtime.bigint();
  const endMemory = process.memoryUsage();
  const duration = Number(endTime - global.testStartTime) / 1e6; // Convert to ms
  const memoryDelta = endMemory.heapUsed - global.testStartMemory.heapUsed;
  
  // Warn about slow tests
  if (duration > 5000) {
    console.warn(`Slow test detected: ${duration.toFixed(2)}ms`);
  }
  
  // Warn about memory leaks
  if (memoryDelta > 50 * 1024 * 1024) { // 50MB
    console.warn(`Potential memory leak: ${(memoryDelta / 1024 / 1024).toFixed(2)}MB increase`);
  }
});

// Cleanup after all tests
afterAll(() => {
  // Force garbage collection if available
  if (global.gc) {
    global.gc();
  }
});