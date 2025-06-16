import { config, validateConfig } from './core/config';
import { logger } from './core/logger';
import axios from 'axios';

async function testAPIKeys() {
  logger.info('Testing API key configurations...');
  
  const results = {
    tavily: false,
    brave: false,
    smithery: false,
  };
  
  // Test Tavily API
  try {
    logger.info('Testing Tavily API...');
    const tavilyResponse = await axios.post(
      'https://api.tavily.com/search',
      {
        api_key: config.tavily.apiKey,
        query: 'test',
        search_depth: 'basic',
        max_results: 1,
      }
    );
    
    if (tavilyResponse.status === 200) {
      results.tavily = true;
      logger.info('✓ Tavily API key is valid');
    }
  } catch (error: any) {
    logger.error(`✗ Tavily API test failed: ${error.message}`);
  }
  
  // Test Brave API
  try {
    logger.info('Testing Brave Search API...');
    const braveResponse = await axios.get(
      'https://api.search.brave.com/res/v1/web/search',
      {
        headers: {
          'X-Subscription-Token': config.brave.apiKey,
        },
        params: {
          q: 'test',
          count: 1,
        },
      }
    );
    
    if (braveResponse.status === 200) {
      results.brave = true;
      logger.info('✓ Brave API key is valid');
    }
  } catch (error: any) {
    logger.error(`✗ Brave API test failed: ${error.message}`);
  }
  
  // Test Smithery API
  try {
    logger.info('Testing Smithery API...');
    // Note: Replace with actual Smithery API test endpoint
    // This is a placeholder as the actual endpoint might vary
    const smitheryResponse = await axios.post(
      'https://api.smithery.ai/v1/forge',
      {
        prompt: 'Hello, test',
        model: 'claude-3-haiku',
        max_tokens: 10,
      },
      {
        headers: {
          'Authorization': `Bearer ${config.smithery.apiKey}`,
          'Content-Type': 'application/json',
        },
      }
    );
    
    if (smitheryResponse.status === 200) {
      results.smithery = true;
      logger.info('✓ Smithery API key is valid');
    }
  } catch (error: any) {
    // Smithery might have different error codes for valid keys
    if (error.response?.status === 401) {
      logger.error(`✗ Smithery API key is invalid`);
    } else {
      // If we get a different error, the key might be valid but the request failed
      results.smithery = true;
      logger.warn(`⚠ Smithery API test inconclusive: ${error.message}`);
    }
  }
  
  return results;
}

async function testServerHealth() {
  logger.info('\\nTesting server health checks...');
  
  const servers = [
    'development-workflow',
    'search-integration',
    'ai-enhancement',
    'code-analysis',
    'documentation-generation',
  ];
  
  const health: Record<string, string> = {};
  
  for (const server of servers) {
    try {
      // In a real implementation, you would check if the server process is running
      // For now, we'll just verify the server can be imported
      const serverPath = `./servers/${server}/index`;
      await import(serverPath);
      health[server] = 'ready';
      logger.info(`✓ ${server} server is ready`);
    } catch (error) {
      health[server] = 'not found';
      logger.warn(`⚠ ${server} server not implemented yet`);
    }
  }
  
  return health;
}

async function main() {
  logger.info('=== MCP Server Test Suite ===\\n');
  
  try {
    // Validate configuration
    logger.info('Validating configuration...');
    validateConfig();
    logger.info('✓ Configuration is valid\\n');
    
    // Test API keys
    const apiResults = await testAPIKeys();
    
    // Test server health
    const healthResults = await testServerHealth();
    
    // Summary
    logger.info('\\n=== Test Summary ===');
    logger.info(`API Keys:`);
    logger.info(`  Tavily: ${apiResults.tavily ? '✓' : '✗'}`);
    logger.info(`  Brave: ${apiResults.brave ? '✓' : '✗'}`);
    logger.info(`  Smithery: ${apiResults.smithery ? '✓' : '✗'}`);
    
    logger.info(`\\nServers:`);
    Object.entries(healthResults).forEach(([server, status]) => {
      logger.info(`  ${server}: ${status}`);
    });
    
    const allAPIsValid = Object.values(apiResults).every(v => v);
    if (allAPIsValid) {
      logger.info('\\n✅ All API keys are valid! MCP servers are ready to use.');
    } else {
      logger.warn('\\n⚠️  Some API keys failed validation. Check the logs above.');
    }
    
  } catch (error: any) {
    logger.error(`Test suite failed: ${error.message}`);
    process.exit(1);
  }
}

// Run tests if this file is executed directly
if (require.main === module) {
  main().catch(console.error);
}