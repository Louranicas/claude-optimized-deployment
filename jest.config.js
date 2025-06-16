/**
 * Jest configuration for MCP Server testing framework
 * Supports TypeScript, JavaScript, and Node.js MCP servers
 */
module.exports = {
  // Test environment
  testEnvironment: 'node',
  
  // Root directories for tests
  roots: ['<rootDir>/tests', '<rootDir>/src'],
  
  // Test file patterns
  testMatch: [
    '**/__tests__/**/*.(js|ts)',
    '**/*.(test|spec).(js|ts)',
    '**/tests/**/test_*.js',
    '**/tests/**/test_*.ts'
  ],
  
  // TypeScript support
  transform: {
    '^.+\\.(ts|tsx)$': 'ts-jest',
    '^.+\\.(js|jsx)$': 'babel-jest'
  },
  
  // Module file extensions
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  
  // Setup files
  setupFilesAfterEnv: [
    '<rootDir>/tests/jest.setup.js'
  ],
  
  // Module name mapping for absolute imports
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@tests/(.*)$': '<rootDir>/tests/$1',
    '^@mcp/(.*)$': '<rootDir>/src/mcp/$1'
  },
  
  // Coverage configuration
  collectCoverage: true,
  coverageDirectory: 'coverage',
  coverageReporters: [
    'text',
    'lcov',
    'html',
    'json',
    'cobertura'
  ],
  
  // Coverage thresholds
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    },
    // MCP server specific thresholds
    './src/mcp/': {
      branches: 85,
      functions: 85,
      lines: 85,
      statements: 85
    }
  },
  
  // Files to collect coverage from
  collectCoverageFrom: [
    'src/**/*.{js,ts}',
    '!src/**/*.d.ts',
    '!src/**/*.config.{js,ts}',
    '!src/**/index.{js,ts}',
    '!**/node_modules/**',
    '!**/vendor/**'
  ],
  
  // Test timeout
  testTimeout: 30000,
  
  // Global test setup
  globalSetup: '<rootDir>/tests/global.setup.js',
  globalTeardown: '<rootDir>/tests/global.teardown.js',
  
  // Memory optimization for large test suites
  maxWorkers: '50%',
  maxConcurrency: 5,
  
  // Error handling
  bail: false,
  verbose: true,
  
  // Mock configuration
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,
  
  // Reporter configuration
  reporters: [
    'default',
    ['jest-junit', {
      outputDirectory: 'test-results',
      outputName: 'jest-results.xml'
    }],
    ['jest-html-reporters', {
      publicPath: './test-results',
      filename: 'jest-report.html',
      expand: true
    }]
  ],
  
  // Performance monitoring
  detectOpenHandles: true,
  detectLeaks: true,
  forceExit: true,
  
  // Cache configuration
  cacheDirectory: '<rootDir>/.jest-cache',
  
  // Ignore patterns
  testPathIgnorePatterns: [
    '/node_modules/',
    '/coverage/',
    '/test-results/',
    '\\.cache/',
    'backup_'
  ],
  
  // Watch mode configuration
  watchPathIgnorePatterns: [
    '/node_modules/',
    '/coverage/',
    '/test-results/'
  ]
};