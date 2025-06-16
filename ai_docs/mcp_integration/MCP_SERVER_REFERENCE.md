# MCP Server Reference Guide

## Complete Server List (28 Servers)

### Deployment Orchestration
0. **deploy-code-orchestrator**
   - Source: Internal (deploy-code-module)
   - Capabilities: Automated deployment workflows, blue-green deployments, rollback management
   - Status: ✅ Operational
   - Integration: Native CODE integration

### Desktop Control
1. **desktop-commander** (@wonderwhy-er)
   - Source: Smithery
   - Capabilities: Command execution, system control
   - Status: ✅ Operational

### Search Services
2. **brave-search**
   - API-based web search
   - API Key: Configured
   
3. **tavily-mcp**
   - AI-powered search
   - Advanced web extraction

### Databases
4. **postgresql** - Relational database
5. **sqlite** - Local database
6. **redis** - High-speed cache

### File & Version Control
7. **filesystem** - File operations
8. **github** - Repository management

### AI Enhancement
9. **memory** - Context persistence
10. **sequential-thinking** - Complex reasoning

### Automation
11. **puppeteer** - Browser automation

### Cloud Services
12. **gdrive** - Google Drive
13. **google-maps** - Location services
14. **vercel-mcp-adapter** - Deployment

### Development
15. **smithery-sdk** - MCP development
16. **everything** - Protocol testing

### System Integration
17. **docker** - Containers
18. **kubernetes** - Orchestration
19. **windows-system** - Windows control
20. **azure-devops** - CI/CD

### Communication
21. **slack** - Team messaging

### Monitoring & Security
22. **prometheus** - Metrics
23. **security-scanner** - Security checks

### Storage
24. **s3-storage** - AWS S3
25. **cloud-storage** - Generic cloud
26. **s3** - S3 compatible
27. **cloud** - Multi-cloud

## Usage Examples

### Deploy-Code Orchestrator
```bash
# Execute deployment through MCP
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"deploy_service","arguments":{"service":"api","strategy":"blue_green"}},"id":1}' | \
  node deploy-code-module/src/mcp-server.js

# Monitor deployment status
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_deployment_status","arguments":{"deployment_id":"deploy-123"}},"id":2}' | \
  node deploy-code-module/src/mcp-server.js

# Emergency rollback
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"emergency_rollback","arguments":{"deployment_id":"deploy-123"}},"id":3}' | \
  node deploy-code-module/src/mcp-server.js
```

### Desktop Control
```bash
npx -y @wonderwhy-er/desktop-commander "ls -la"
```

### Sequential Thinking
```bash
npx -y @modelcontextprotocol/server-sequential-thinking   "Break down this complex problem step by step"
```

### Redis Caching
```bash
npx -y @modelcontextprotocol/server-redis SET key "value"
npx -y @modelcontextprotocol/server-redis GET key
```

## Configuration
All servers configured in:
`~/Library/Application Support/Claude/claude_desktop_config.json`

## Last Updated
2025-06-07 13:08
