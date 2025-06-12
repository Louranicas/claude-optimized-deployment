/**
 * Official JavaScript/Node.js Client for Claude-Optimized Deployment Engine (CODE) API
 * 
 * A comprehensive, production-ready JavaScript client with automatic retry logic,
 * rate limiting, error handling, and TypeScript support.
 * 
 * Installation:
 *   npm install axios
 * 
 * Usage:
 *   const client = new CODEClient('http://localhost:8000', 'your-api-key');
 *   try {
 *     const result = await client.mcp.execute('docker', 'docker_ps', {});
 *     console.log(result);
 *   } finally {
 *     // Always clean up to prevent memory leaks
 *     client.destroy();
 *   }
 * 
 * Memory Management:
 *   - Always call client.destroy() when done to prevent memory leaks
 *   - Event listeners are automatically cleaned up on destroy
 *   - Timers and intervals are tracked and cleared automatically
 *   - Process/window cleanup handlers are registered automatically
 */

const axios = require('axios');
const crypto = require('crypto');
const EventEmitter = require('events');

// Event types enum
const EventType = {
    DEPLOYMENT_STARTED: 'deployment.started',
    DEPLOYMENT_COMPLETED: 'deployment.completed',
    DEPLOYMENT_FAILED: 'deployment.failed',
    SECURITY_VULNERABILITY_FOUND: 'security.vulnerability_found',
    CIRCUIT_BREAKER_OPENED: 'circuit_breaker.opened',
    ALERT_TRIGGERED: 'alert.triggered'
};

/**
 * Base error class for CODE API errors
 */
class CODEError extends Error {
    constructor(message, statusCode = null, responseData = {}) {
        super(message);
        this.name = 'CODEError';
        this.statusCode = statusCode;
        this.responseData = responseData;
    }
}

/**
 * Rate limit exceeded error
 */
class RateLimitError extends CODEError {
    constructor(retryAfter, message = 'Rate limit exceeded') {
        super(message, 429);
        this.name = 'RateLimitError';
        this.retryAfter = retryAfter;
    }
}

/**
 * Handle rate limiting with exponential backoff
 */
class RateLimitHandler {
    constructor(baseDelay = 1000, maxDelay = 60000) {
        this.baseDelay = baseDelay;
        this.maxDelay = maxDelay;
        this.currentDelay = baseDelay;
        this.requestTimes = [];
        this.timers = new Set(); // Track all timers for cleanup
    }

    resetDelay() {
        this.currentDelay = this.baseDelay;
    }

    increaseDelay() {
        this.currentDelay = Math.min(this.currentDelay * 2, this.maxDelay);
    }

    shouldWait(requestsPerMinute = 100) {
        const now = Date.now();
        this.requestTimes = this.requestTimes.filter(time => now - time < 60000);

        if (this.requestTimes.length >= requestsPerMinute) {
            return 60000 - (now - this.requestTimes[0]);
        }

        return 0;
    }

    recordRequest() {
        this.requestTimes.push(Date.now());
    }

    sleep(ms) {
        return new Promise(resolve => {
            const timerId = setTimeout(() => {
                this.timers.delete(timerId);
                resolve();
            }, ms);
            this.timers.add(timerId);
        });
    }
    
    /**
     * Clean up all pending timers
     */
    cleanup() {
        this.timers.forEach(timerId => clearTimeout(timerId));
        this.timers.clear();
        this.requestTimes = [];
    }
}

/**
 * Circuit breaker management API
 */
class CircuitBreakersAPI {
    constructor(client) {
        this.client = client;
    }

    async getStatus() {
        return await this.client._request('GET', '/api/circuit-breakers/status');
    }

    async listAll(state = null) {
        const params = {};
        if (state) params.state = state;
        return await this.client._request('GET', '/api/circuit-breakers/breakers', { params });
    }

    async get(breakerName) {
        return await this.client._request('GET', `/api/circuit-breakers/breakers/${breakerName}`);
    }

    async reset(breakerName) {
        return await this.client._request('POST', `/api/circuit-breakers/breakers/${breakerName}/reset`);
    }

    async resetAll() {
        return await this.client._request('POST', '/api/circuit-breakers/breakers/reset-all');
    }

    async getHealth() {
        return await this.client._request('GET', '/api/circuit-breakers/health');
    }

    async getAlerts(limit = 10) {
        return await this.client._request('GET', '/api/circuit-breakers/alerts', { params: { limit } });
    }

    async startMonitoring(config = {}) {
        return await this.client._request('POST', '/api/circuit-breakers/monitoring/start', { params: config });
    }

    async stopMonitoring() {
        return await this.client._request('POST', '/api/circuit-breakers/monitoring/stop');
    }
}

/**
 * MCP (Model Context Protocol) tools API
 */
class MCPAPI {
    constructor(client) {
        this.client = client;
    }

    async listServers() {
        return await this.client._request('GET', '/api/mcp/servers');
    }

    async getServerTools(serverName) {
        return await this.client._request('GET', `/api/mcp/servers/${serverName}/tools`);
    }

    async execute(server, tool, args) {
        const payload = { server, tool, arguments: args };
        return await this.client._request('POST', '/api/mcp/execute', { data: payload });
    }

    // Convenience methods for common operations
    async dockerBuild(dockerfilePath, imageTag, options = {}) {
        const args = {
            dockerfile_path: dockerfilePath,
            image_tag: imageTag,
            ...options
        };
        return await this.execute('docker', 'docker_build', args);
    }

    async dockerRun(image, containerName = null, options = {}) {
        const args = { image, ...options };
        if (containerName) args.container_name = containerName;
        return await this.execute('docker', 'docker_run', args);
    }

    async dockerPs(allContainers = false, options = {}) {
        const args = { all: allContainers, ...options };
        return await this.execute('docker', 'docker_ps', args);
    }

    async kubectlApply(manifestPath, namespace = null, options = {}) {
        const args = { manifest_path: manifestPath, ...options };
        if (namespace) args.namespace = namespace;
        return await this.execute('kubernetes', 'kubectl_apply', args);
    }

    async kubectlGet(resource, name = null, namespace = null, options = {}) {
        const args = { resource, ...options };
        if (name) args.name = name;
        if (namespace) args.namespace = namespace;
        return await this.execute('kubernetes', 'kubectl_get', args);
    }

    async securityScanNpm(packageJsonPath, options = {}) {
        const args = { package_json_path: packageJsonPath, ...options };
        return await this.execute('security-scanner', 'npm_audit', args);
    }

    async securityScanDocker(imageName, options = {}) {
        const args = { image_name: imageName, ...options };
        return await this.execute('security-scanner', 'docker_security_scan', args);
    }

    async slackNotify(channel, message, options = {}) {
        const args = { channel, message, ...options };
        return await this.execute('slack-notifications', 'send_notification', args);
    }

    async prometheusQuery(query, options = {}) {
        const args = { query, ...options };
        return await this.execute('prometheus-monitoring', 'prometheus_query', args);
    }

    async s3Upload(localPath, bucket, key, options = {}) {
        const args = { local_path: localPath, bucket, key, ...options };
        return await this.execute('s3-storage', 's3_upload_file', args);
    }
}

/**
 * AI expert consultation API
 */
class ExpertsAPI {
    constructor(client) {
        this.client = client;
    }

    async consult(query, expertTypes = null, options = {}) {
        const payload = { query, ...options };
        if (expertTypes) payload.expert_types = expertTypes;
        return await this.client._request('POST', '/api/experts/consult', { data: payload });
    }

    async getHealth() {
        return await this.client._request('GET', '/api/experts/health');
    }
}

/**
 * Deployment management API
 */
class DeploymentsAPI {
    constructor(client) {
        this.client = client;
    }

    async create(config) {
        return await this.client._request('POST', '/api/deployments', { data: config });
    }

    async get(deploymentId) {
        return await this.client._request('GET', `/api/deployments/${deploymentId}`);
    }

    async getLogs(deploymentId, follow = false, tail = 100) {
        const params = { follow, tail };
        
        if (follow) {
            // For streaming logs, return a promise that resolves to a stream
            return this._streamLogs(deploymentId, params);
        } else {
            return await this.client._request('GET', `/api/deployments/${deploymentId}/logs`, { params });
        }
    }

    async _streamLogs(deploymentId, params) {
        // This would require SSE or WebSocket implementation
        // For now, return a simple implementation
        const response = await this.client._request('GET', `/api/deployments/${deploymentId}/logs`, { params });
        return response;
    }
}

/**
 * Security scanning and management API
 */
class SecurityAPI {
    constructor(client) {
        this.client = client;
    }

    async scan(scanConfig) {
        return await this.client._request('POST', '/api/security/scan', { data: scanConfig });
    }

    async listVulnerabilities(severity = null, fixed = null) {
        const params = {};
        if (severity) params.severity = severity;
        if (fixed !== null) params.fixed = fixed;
        return await this.client._request('GET', '/api/security/vulnerabilities', { params });
    }
}

/**
 * System monitoring and metrics API
 */
class MonitoringAPI {
    constructor(client) {
        this.client = client;
    }

    async getMetrics(metricNames = null) {
        const params = {};
        if (metricNames) params.metric_names = metricNames.join(',');
        return await this.client._request('GET', '/api/monitoring/metrics', { params });
    }

    async getAlerts(severity = null, acknowledged = null) {
        const params = {};
        if (severity) params.severity = severity;
        if (acknowledged !== null) params.acknowledged = acknowledged;
        return await this.client._request('GET', '/api/monitoring/alerts', { params });
    }
}

/**
 * Webhook management API
 */
class WebhooksAPI {
    constructor(client) {
        this.client = client;
    }

    async register(config) {
        return await this.client._request('POST', '/api/webhooks', { data: config });
    }

    async list() {
        return await this.client._request('GET', '/api/webhooks');
    }

    async update(webhookId, config) {
        return await this.client._request('PUT', `/api/webhooks/${webhookId}`, { data: config });
    }

    async delete(webhookId) {
        await this.client._request('DELETE', `/api/webhooks/${webhookId}`);
        return true;
    }

    static verifySignature(payload, signature, secret) {
        const expectedSignature = crypto
            .createHmac('sha256', secret)
            .update(payload, 'utf8')
            .digest('hex');

        const actualSignature = signature.startsWith('sha256=')
            ? signature.slice(7)
            : signature;

        return crypto.timingSafeEqual(
            Buffer.from(expectedSignature, 'hex'),
            Buffer.from(actualSignature, 'hex')
        );
    }
}

/**
 * Comprehensive JavaScript client for the CODE API
 * 
 * Features:
 * - Promise-based async operations
 * - Automatic retry with exponential backoff
 * - Rate limiting handling
 * - Comprehensive error handling
 * - Event emitter for monitoring
 * - Built-in logging
 * - Automatic memory management and cleanup
 * 
 * Example:
 *   const client = new CODEClient('http://localhost:8000', 'your-api-key');
 *   
 *   try {
 *     // Get system health
 *     const health = await client.circuitBreakers.getHealth();
 *     
 *     // Execute MCP tools
 *     const containers = await client.mcp.dockerPs();
 *     
 *     // Deploy application
 *     const deployment = await client.deployments.create({
 *       application_name: 'my-app',
 *       environment: 'production',
 *       deployment_type: 'kubernetes',
 *       source: {
 *         type: 'git',
 *         repository: 'https://github.com/me/my-app.git'
 *       }
 *     });
 *   } finally {
 *     // Always clean up to prevent memory leaks
 *     client.destroy();
 *   }
 */
class CODEClient extends EventEmitter {
    constructor(
        baseUrl = 'http://localhost:8000',
        apiKey = null,
        options = {}
    ) {
        super();

        this.baseUrl = baseUrl.replace(/\/$/, '');
        this.apiKey = apiKey;
        this.timeout = options.timeout || 30000;
        this.maxRetries = options.maxRetries || 3;
        this.retryBackoff = options.retryBackoff || 1000;
        this.debug = options.debug || false;

        // Rate limiting
        this.rateLimiter = new RateLimitHandler(this.retryBackoff);
        
        // Memory management
        this.isDestroyed = false;
        this.timers = new Set();
        this.intervals = new Set();

        // HTTP client
        this.httpClient = axios.create({
            timeout: this.timeout,
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'CODE-JavaScript-Client/1.0.0'
            }
        });

        // Add API key to headers if provided
        if (this.apiKey) {
            this.httpClient.defaults.headers['X-API-Key'] = this.apiKey;
        }

        // API sections
        this.circuitBreakers = new CircuitBreakersAPI(this);
        this.mcp = new MCPAPI(this);
        this.experts = new ExpertsAPI(this);
        this.deployments = new DeploymentsAPI(this);
        this.security = new SecurityAPI(this);
        this.monitoring = new MonitoringAPI(this);
        this.webhooks = new WebhooksAPI(this);

        // Add request/response interceptors for logging
        if (this.debug) {
            this._setupLogging();
        }
        
        // Setup cleanup on process termination
        this._setupProcessCleanup();
    }

    _setupLogging() {
        this.httpClient.interceptors.request.use(
            (config) => {
                if (!this.isDestroyed) {
                    console.log(`[CODE Client] ${config.method.toUpperCase()} ${config.url}`);
                }
                return config;
            },
            (error) => {
                if (!this.isDestroyed) {
                    console.error('[CODE Client] Request error:', error);
                }
                return Promise.reject(error);
            }
        );

        this.httpClient.interceptors.response.use(
            (response) => {
                if (!this.isDestroyed) {
                    console.log(`[CODE Client] ${response.status} ${response.config.url}`);
                }
                return response;
            },
            (error) => {
                if (!this.isDestroyed) {
                    console.error('[CODE Client] Response error:', error.response?.status, error.message);
                }
                return Promise.reject(error);
            }
        );
    }
    
    /**
     * Setup process cleanup handlers
     * @private
     */
    _setupProcessCleanup() {
        const cleanup = () => this.destroy();
        
        // Node.js process events
        if (typeof process !== 'undefined') {
            process.on('exit', cleanup);
            process.on('SIGINT', cleanup);
            process.on('SIGTERM', cleanup);
            process.on('uncaughtException', cleanup);
        }
        
        // Browser events
        if (typeof window !== 'undefined') {
            window.addEventListener('beforeunload', cleanup);
            window.addEventListener('pagehide', cleanup);
        }
    }

    async _request(method, path, config = {}) {
        const url = `${this.baseUrl}${path}`;

        // Check if client is destroyed
        if (this.isDestroyed) {
            throw new CODEError('Client has been destroyed');
        }
        
        // Check rate limiting
        const waitTime = this.rateLimiter.shouldWait();
        if (waitTime > 0) {
            if (this.debug && !this.isDestroyed) console.log(`[CODE Client] Rate limiting: waiting ${waitTime}ms`);
            await this.rateLimiter.sleep(waitTime);
        }

        for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
            try {
                this.rateLimiter.recordRequest();

                const response = await this.httpClient.request({
                    method,
                    url,
                    ...config
                });

                // Process rate limit headers
                const remaining = parseInt(response.headers['x-ratelimit-remaining'] || '0');
                const resetTime = parseInt(response.headers['x-ratelimit-reset'] || '0');

                if (response.status === 200 || response.status === 201) {
                    this.rateLimiter.resetDelay();
                    if (!this.isDestroyed) {
                        this.emit('response', { method, path, status: response.status, attempt });
                    }
                    return response.data;
                }

                // Handle non-success status codes
                const errorData = response.data || {};
                const errorMessage = errorData.error?.message || `HTTP ${response.status}`;
                throw new CODEError(errorMessage, response.status, errorData);

            } catch (error) {
                if (error.response?.status === 429) {
                    // Rate limit exceeded
                    const retryAfter = parseInt(error.response.headers['retry-after'] || this.rateLimiter.currentDelay / 1000);

                    if (attempt < this.maxRetries && !this.isDestroyed) {
                        const waitMs = retryAfter * 1000;
                        if (this.debug && !this.isDestroyed) console.log(`[CODE Client] Rate limited. Retrying in ${retryAfter}s (attempt ${attempt + 1})`);
                        await this.rateLimiter.sleep(waitMs);
                        this.rateLimiter.increaseDelay();
                        if (!this.isDestroyed) {
                            this.emit('retry', { method, path, attempt, reason: 'rate_limit', waitMs });
                        }
                        continue;
                    } else {
                        const errorData = error.response?.data || {};
                        throw new RateLimitError(retryAfter, `Rate limit exceeded after ${this.maxRetries} retries`);
                    }
                }

                if (error.response?.status === 503) {
                    // Service unavailable
                    const retryAfter = parseInt(error.response.headers['retry-after'] || '60');

                    if (attempt < this.maxRetries && !this.isDestroyed) {
                        const waitMs = retryAfter * 1000;
                        if (this.debug && !this.isDestroyed) console.log(`[CODE Client] Service unavailable. Retrying in ${retryAfter}s (attempt ${attempt + 1})`);
                        await this.rateLimiter.sleep(waitMs);
                        if (!this.isDestroyed) {
                            this.emit('retry', { method, path, attempt, reason: 'service_unavailable', waitMs });
                        }
                        continue;
                    } else {
                        const errorData = error.response?.data || {};
                        throw new CODEError('Service unavailable after retries', 503, errorData);
                    }
                }

                if (error.response) {
                    // HTTP error response
                    const errorData = error.response.data || {};
                    const errorMessage = errorData.error?.message || `HTTP ${error.response.status}`;
                    throw new CODEError(errorMessage, error.response.status, errorData);
                }

                // Network or other errors
                if (attempt < this.maxRetries && !this.isDestroyed) {
                    const waitMs = this.rateLimiter.currentDelay;
                    if (this.debug && !this.isDestroyed) console.log(`[CODE Client] Request failed: ${error.message}. Retrying in ${waitMs}ms (attempt ${attempt + 1})`);
                    await this.rateLimiter.sleep(waitMs);
                    this.rateLimiter.increaseDelay();
                    if (!this.isDestroyed) {
                        this.emit('retry', { method, path, attempt, reason: 'network_error', waitMs });
                    }
                    continue;
                } else {
                    throw new CODEError(`Request failed after ${this.maxRetries} retries: ${error.message}`);
                }
            }
        }
    }

    async healthCheck() {
        return await this._request('GET', '/health');
    }

    // Convenience methods for common workflows
    async deployApplication(appName, environment, source, options = {}) {
        const config = {
            application_name: appName,
            environment,
            deployment_type: 'kubernetes',
            source,
            ...options
        };
        return await this.deployments.create(config);
    }

    async buildAndDeploy(dockerfilePath, imageTag, k8sManifestPath, namespace = 'default') {
        // Build Docker image
        console.log(`Building Docker image: ${imageTag}`);
        const buildResult = await this.mcp.dockerBuild(dockerfilePath, imageTag);

        if (!buildResult.success) {
            throw new CODEError(`Docker build failed: ${buildResult.error}`);
        }

        // Deploy to Kubernetes
        console.log(`Deploying to Kubernetes namespace: ${namespace}`);
        const deployResult = await this.mcp.kubectlApply(k8sManifestPath, namespace);

        if (!deployResult.success) {
            throw new CODEError(`Kubernetes deployment failed: ${deployResult.error}`);
        }

        return {
            buildResult,
            deployResult,
            imageTag,
            namespace
        };
    }

    async securityAudit(projectPath = '.') {
        const results = {};

        // NPM audit if package.json exists
        try {
            const npmResult = await this.mcp.securityScanNpm(`${projectPath}/package.json`);
            results.npmAudit = npmResult;
        } catch (error) {
            if (this.debug) console.log('No package.json found, skipping NPM audit');
        }

        // Python safety check if requirements.txt exists
        try {
            const pythonResult = await this.mcp.execute(
                'security-scanner',
                'python_safety_check',
                { requirements_path: `${projectPath}/requirements.txt` }
            );
            results.pythonSafety = pythonResult;
        } catch (error) {
            if (this.debug) console.log('No requirements.txt found, skipping Python safety check');
        }

        // File security scan
        try {
            const fileResult = await this.mcp.execute(
                'security-scanner',
                'file_security_scan',
                { file_path: projectPath, recursive: true }
            );
            results.fileScan = fileResult;
        } catch (error) {
            console.warn('File security scan failed:', error.message);
        }

        return results;
    }
    
    /**
     * Properly destroy the client and clean up all resources
     * This prevents memory leaks by removing all event listeners and clearing timers
     */
    destroy() {
        if (this.isDestroyed) {
            return;
        }
        
        this.isDestroyed = true;
        
        // Clean up rate limiter
        if (this.rateLimiter) {
            this.rateLimiter.cleanup();
        }
        
        // Clear all timers
        this.timers.forEach(timerId => clearTimeout(timerId));
        this.timers.clear();
        
        // Clear all intervals
        this.intervals.forEach(intervalId => clearInterval(intervalId));
        this.intervals.clear();
        
        // Remove all event listeners
        this.removeAllListeners();
        
        // Clear HTTP client
        if (this.httpClient) {
            // Cancel any pending requests
            this.httpClient.defaults.timeout = 1;
        }
        
        if (this.debug) {
            console.log('[CODE Client] Client destroyed and resources cleaned up');
        }
    }
    
    /**
     * Set a timeout that will be automatically cleaned up when the client is destroyed
     * @param {Function} callback - The callback function
     * @param {number} delay - Delay in milliseconds
     * @returns {number} Timer ID
     */
    setTimeout(callback, delay) {
        if (this.isDestroyed) {
            throw new CODEError('Cannot set timeout on destroyed client');
        }
        
        const timerId = setTimeout(() => {
            this.timers.delete(timerId);
            if (!this.isDestroyed) {
                callback();
            }
        }, delay);
        
        this.timers.add(timerId);
        return timerId;
    }
    
    /**
     * Set an interval that will be automatically cleaned up when the client is destroyed
     * @param {Function} callback - The callback function
     * @param {number} delay - Delay in milliseconds
     * @returns {number} Interval ID
     */
    setInterval(callback, delay) {
        if (this.isDestroyed) {
            throw new CODEError('Cannot set interval on destroyed client');
        }
        
        const intervalId = setInterval(() => {
            if (!this.isDestroyed) {
                callback();
            } else {
                clearInterval(intervalId);
                this.intervals.delete(intervalId);
            }
        }, delay);
        
        this.intervals.add(intervalId);
        return intervalId;
    }
    
    /**
     * Clear a timeout managed by this client
     * @param {number} timerId - The timer ID to clear
     */
    clearTimeout(timerId) {
        clearTimeout(timerId);
        this.timers.delete(timerId);
    }
    
    /**
     * Clear an interval managed by this client
     * @param {number} intervalId - The interval ID to clear
     */
    clearInterval(intervalId) {
        clearInterval(intervalId);
        this.intervals.delete(intervalId);
    }
}

// Export classes and enums
module.exports = {
    CODEClient,
    CODEError,
    RateLimitError,
    EventType,
    
    // API classes for advanced usage
    CircuitBreakersAPI,
    MCPAPI,
    ExpertsAPI,
    DeploymentsAPI,
    SecurityAPI,
    MonitoringAPI,
    WebhooksAPI
};

// Example usage functions
async function exampleBasicUsage() {
    const client = new CODEClient('http://localhost:8000', 'your-api-key');

    try {
        // Check system health
        const health = await client.circuitBreakers.getHealth();
        console.log(`System health: ${health.health}`);

        // List Docker containers
        const containers = await client.mcp.dockerPs();
        console.log(`Running containers: ${containers.result.containers.length}`);

        // Get system metrics
        const metrics = await client.monitoring.getMetrics(['cpu_usage', 'memory_usage']);
        console.log('Current metrics:', metrics);

    } catch (error) {
        console.error('API call failed:', error.message);
    } finally {
        // Always clean up resources
        client.destroy();
    }
}

async function exampleDeploymentWorkflow() {
    const client = new CODEClient('http://localhost:8000', 'your-api-key', { debug: true });

    // Listen for events (these will be automatically cleaned up when client is destroyed)
    client.on('retry', (data) => {
        console.log(`Retrying ${data.method} ${data.path} due to ${data.reason}`);
    });

    try {
        // Security audit first
        console.log('🔍 Running security audit...');
        const auditResults = await client.securityAudit('.');

        // Check for critical vulnerabilities
        const criticalIssues = Object.values(auditResults)
            .filter(result => result.success)
            .reduce((sum, result) => sum + (result.result?.vulnerabilities?.critical || 0), 0);

        if (criticalIssues > 0) {
            console.log(`❌ Found ${criticalIssues} critical security issues. Aborting deployment.`);
            return;
        }

        // Build and deploy
        console.log('🏗️ Building and deploying...');
        const result = await client.buildAndDeploy(
            '.',
            'my-app:latest',
            './k8s/',
            'production'
        );

        // Send notification
        await client.mcp.slackNotify(
            '#deployments',
            `🚀 Deployment completed: ${result.imageTag}`,
            { severity: 'success' }
        );

        console.log('✅ Deployment completed successfully!');

    } catch (error) {
        console.error(`❌ Deployment failed: ${error.message}`);

        // Send failure notification
        try {
            await client.mcp.slackNotify(
                '#alerts',
                `❌ Deployment failed: ${error.message}`,
                { severity: 'error' }
            );
        } catch (notificationError) {
            console.error('Failed to send notification:', notificationError.message);
        }
    } finally {
        // Always clean up resources
        client.destroy();
    }
}

async function exampleMonitoringSetup() {
    const client = new CODEClient('http://localhost:8000', 'your-api-key');

    try {
        // Register webhook for deployment events
        const webhookConfig = {
            url: 'https://your-app.com/webhooks/code',
            events: [
                EventType.DEPLOYMENT_COMPLETED,
                EventType.DEPLOYMENT_FAILED,
                EventType.SECURITY_VULNERABILITY_FOUND
            ],
            secret: 'your-webhook-secret'
        };

        const webhook = await client.webhooks.register(webhookConfig);
        console.log(`Webhook registered: ${webhook.webhook_id}`);

        // Start circuit breaker monitoring
        await client.circuitBreakers.startMonitoring({
            check_interval: 10,
            alert_on_open: true,
            alert_on_half_open: true
        });

        console.log('Monitoring started successfully!');

    } catch (error) {
        console.error('Monitoring setup failed:', error.message);
    } finally {
        // Note: In monitoring setup, you might want to keep the client alive
        // Only destroy when shutting down the monitoring system
        // client.destroy();
    }
}

// Webhook handler example for Express.js
function createWebhookHandler(secret) {
    return (req, res) => {
        const signature = req.headers['x-code-signature'];
        const payload = JSON.stringify(req.body);

        // Verify signature
        if (!WebhooksAPI.verifySignature(payload, signature, secret)) {
            console.warn('Invalid webhook signature');
            return res.status(401).json({ error: 'Invalid signature' });
        }

        const eventData = req.body;
        const eventType = eventData.event;
        const deliveryId = eventData.delivery_id;

        console.log(`Received webhook: ${eventType} (${deliveryId})`);

        // Handle different event types
        switch (eventType) {
            case EventType.DEPLOYMENT_COMPLETED:
                handleDeploymentCompleted(eventData.data);
                break;
            case EventType.DEPLOYMENT_FAILED:
                handleDeploymentFailed(eventData.data);
                break;
            case EventType.SECURITY_VULNERABILITY_FOUND:
                handleVulnerabilityFound(eventData.data);
                break;
            default:
                console.log(`Unhandled event type: ${eventType}`);
        }

        res.status(200).json({ status: 'received', delivery_id: deliveryId });
    };
}

function handleDeploymentCompleted(data) {
    console.log(`✅ Deployment ${data.version} completed successfully!`);
    // Add your business logic here
}

function handleDeploymentFailed(data) {
    console.error(`❌ Deployment ${data.version} failed: ${data.error.message}`);
    // Add your error handling logic here
}

function handleVulnerabilityFound(data) {
    const vuln = data.vulnerability;
    console.warn(`🚨 Security vulnerability found: ${vuln.title} (${vuln.severity})`);
    // Add your security handling logic here
}

// Example Express.js webhook endpoint
/*
const express = require('express');
const app = express();

app.use(express.json());

app.post('/webhooks/code', createWebhookHandler('your-webhook-secret'));

app.listen(3000, () => {
    console.log('Webhook server listening on port 3000');
});
*/

// Run examples if this file is executed directly
if (require.main === module) {
    exampleBasicUsage().catch(console.error);
    // exampleDeploymentWorkflow().catch(console.error);
    // exampleMonitoringSetup().catch(console.error);
}