/**
 * Jest global setup for MCP testing framework
 * Runs once before all tests across all workers
 */

const fs = require('fs').promises;
const path = require('path');

module.exports = async () => {
  console.log('🧪 Setting up MCP Testing Framework...');
  
  try {
    // Create necessary test directories
    const testDirs = [
      'test-results',
      'coverage',
      'test-data',
      'test-logs'
    ];
    
    for (const dir of testDirs) {
      await fs.mkdir(path.join(process.cwd(), dir), { recursive: true });
    }
    
    // Set up test environment variables
    process.env.NODE_ENV = 'test';
    process.env.LOG_LEVEL = 'error';
    process.env.MCP_TEST_MODE = 'true';
    process.env.DISABLE_EXTERNAL_CALLS = 'true';
    
    // Mock API keys for testing
    process.env.ANTHROPIC_API_KEY = 'test-claude-key';
    process.env.OPENAI_API_KEY = 'test-openai-key';
    process.env.GOOGLE_GEMINI_API_KEY = 'test-gemini-key';
    process.env.BRAVE_API_KEY = 'test-brave-key';
    process.env.SLACK_BOT_TOKEN = 'test-slack-token';
    process.env.AWS_ACCESS_KEY_ID = 'test-aws-key';
    process.env.AWS_SECRET_ACCESS_KEY = 'test-aws-secret';
    process.env.AZURE_DEVOPS_TOKEN = 'test-azure-token';
    
    // Create test configuration
    const testConfig = {
      environment: 'test',
      timestamp: new Date().toISOString(),
      testSuiteId: `mcp_test_${Date.now()}`,
      servers: {
        timeout: 30000,
        retries: 3,
        concurrency: 5
      },
      coverage: {
        threshold: {
          statements: 80,
          branches: 80,
          functions: 80,
          lines: 80
        }
      },
      performance: {
        maxTestDuration: 10000,
        memoryThreshold: 100 * 1024 * 1024 // 100MB
      }
    };
    
    await fs.writeFile(
      path.join(process.cwd(), 'test-data', 'test-config.json'),
      JSON.stringify(testConfig, null, 2)
    );
    
    // Initialize test database/storage if needed
    const testData = {
      mockServers: {},
      testResults: [],
      benchmarks: {}
    };
    
    await fs.writeFile(
      path.join(process.cwd(), 'test-data', 'test-storage.json'),
      JSON.stringify(testData, null, 2)
    );
    
    console.log('✅ MCP Testing Framework setup complete');
    
  } catch (error) {
    console.error('❌ Failed to set up test environment:', error);
    throw error;
  }
};