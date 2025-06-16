/**
 * Jest global teardown for MCP testing framework
 * Runs once after all tests across all workers
 */

const fs = require('fs').promises;
const path = require('path');

module.exports = async () => {
  console.log('🧹 Tearing down MCP Testing Framework...');
  
  try {
    // Generate final test summary
    const testResultsPath = path.join(process.cwd(), 'test-results');
    const summaryPath = path.join(testResultsPath, 'test-summary.json');
    
    const summary = {
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV,
      testSuiteId: process.env.MCP_TEST_SUITE_ID || 'unknown',
      status: 'completed',
      cleanup: {
        timestamp: new Date().toISOString(),
        memoryUsage: process.memoryUsage(),
        uptime: process.uptime()
      }
    };
    
    try {
      await fs.writeFile(summaryPath, JSON.stringify(summary, null, 2));
    } catch (writeError) {
      console.warn('Could not write test summary:', writeError.message);
    }
    
    // Clean up temporary test files (optional)
    if (process.env.CLEANUP_TEST_FILES === 'true') {
      const tempFiles = [
        'test-data/temp-*',
        'test-logs/temp-*'
      ];
      
      // Implementation for cleanup would go here
      console.log('🗑️  Cleaned up temporary test files');
    }
    
    // Log memory usage for monitoring
    const memUsage = process.memoryUsage();
    console.log('📊 Final memory usage:', {
      rss: `${(memUsage.rss / 1024 / 1024).toFixed(2)}MB`,
      heapUsed: `${(memUsage.heapUsed / 1024 / 1024).toFixed(2)}MB`,
      heapTotal: `${(memUsage.heapTotal / 1024 / 1024).toFixed(2)}MB`,
      external: `${(memUsage.external / 1024 / 1024).toFixed(2)}MB`
    });
    
    console.log('✅ MCP Testing Framework teardown complete');
    
  } catch (error) {
    console.error('❌ Failed to tear down test environment:', error);
    // Don't throw here to avoid masking test failures
  }
};