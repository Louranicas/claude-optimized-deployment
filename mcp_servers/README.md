# MCP Servers for Claude Optimized Deployment Engine

This directory contains the core MCP (Model Context Protocol) servers that power the Claude Optimized Deployment Engine (CODE). These servers provide specialized AI-enhanced capabilities for development workflows, search integration, code analysis, and more.

## 🚀 Quick Start

1. **Configure API Keys**
   
   The API keys have been securely stored in `config/api_keys.env`. These keys enable:
   - **Tavily**: Advanced web search capabilities
   - **Brave**: Alternative search engine integration
   - **Smithery**: AI-powered text and code enhancements

2. **Install Dependencies**
   ```bash
   npm install
   ```

3. **Build the Project**
   ```bash
   npm run build
   ```

4. **Test API Connectivity**
   ```bash
   npm run test:api
   ```

5. **Start All Servers**
   ```bash
   npm start
   ```

## 📡 Available MCP Servers

### 1. Development Workflow Server
Automates common development tasks and project setup.

**Tools:**
- `create_project_structure`: Create new projects with templates (FastAPI, Express, React, etc.)
- `run_dev_command`: Execute development commands safely
- `generate_boilerplate`: Generate components, services, tests, and more
- `setup_dev_environment`: Configure development environments

### 2. Search Integration Server
Provides unified search capabilities across multiple search engines.

**Tools:**
- `web_search`: Search the web using Tavily and Brave
- `code_search`: Find code examples and documentation
- `research_assistant`: Conduct comprehensive research on topics
- `realtime_info`: Get real-time information (news, weather, stocks)

### 3. AI Enhancement Server
Enhances text and code using advanced AI models via Smithery.

**Tools:**
- `enhance_text`: Improve grammar, clarity, tone, and style
- `enhance_code`: Optimize, refactor, document, or secure code
- `generate_ideas`: Generate creative ideas with constraints
- `solve_problem`: Get structured problem-solving assistance
- `learning_assistant`: Create personalized learning materials

### 4. Code Analysis Server (Coming Soon)
Analyzes code for quality, security, and performance issues.

**Planned Tools:**
- `analyze_code`: Static code analysis
- `find_issues`: Identify bugs and code smells
- `calculate_metrics`: Code complexity and quality metrics
- `security_scan`: Security vulnerability detection

### 5. Documentation Generation Server (Coming Soon)
Automatically generates and maintains documentation.

**Planned Tools:**
- `generate_docs`: Create comprehensive documentation
- `update_readme`: Keep README files up-to-date
- `add_comments`: Add inline code comments
- `create_api_docs`: Generate API documentation

## 🔧 API Endpoints

The MCP Server Manager provides a REST API and WebSocket interface:

- **Health Check**: `GET http://localhost:3000/health`
- **List Servers**: `GET http://localhost:3000/api/servers`
- **Server Details**: `GET http://localhost:3000/api/servers/:name`
- **Start Server**: `POST http://localhost:3000/api/servers/:name/start`
- **Stop Server**: `POST http://localhost:3000/api/servers/:name/stop`
- **Restart Server**: `POST http://localhost:3000/api/servers/:name/restart`
- **System Status**: `GET http://localhost:3000/api/status`
- **WebSocket**: `ws://localhost:3000/ws` (real-time updates)

## 🛠️ Development

### Running in Development Mode
```bash
npm run dev
```

### Running Individual Servers
```bash
npm run start:dev-workflow
npm run start:search
npm run start:ai-enhancement
```

### Testing
```bash
npm test              # Run all tests
npm run test:api      # Test API connectivity
npm run test:watch    # Run tests in watch mode
```

### Building
```bash
npm run build         # Compile TypeScript
npm run typecheck     # Type checking only
```

## 🔒 Security

- API keys are stored securely in `config/api_keys.env`
- Never commit API keys to version control
- Rate limiting is enabled by default
- CORS protection is configured
- All inputs are validated and sanitized

## 📝 Configuration

Environment variables can be set in `config/api_keys.env`:

```env
# API Keys (Required)
TAVILY_API_KEY=your-key
SMITHERY_API_KEY=your-key
BRAVE_API_KEY=your-key

# Server Configuration (Optional)
MCP_SERVER_PORT=3000
MCP_AUTH_ENABLED=true
MCP_LOG_LEVEL=info
MCP_RATE_LIMIT_ENABLED=true
MCP_RATE_LIMIT_WINDOW_MS=60000
MCP_RATE_LIMIT_MAX_REQUESTS=100
```

## 🚀 Production Deployment

### Using systemd (Linux)
```bash
./deploy.sh --systemd --start
```

### Using Docker (Coming Soon)
```bash
docker-compose up -d
```

### Manual Deployment
```bash
npm run build
NODE_ENV=production node dist/index.js
```

## 📊 Monitoring

The server registry provides real-time monitoring via WebSocket. Connect to `ws://localhost:3000/ws` to receive:
- Server status updates
- Start/stop events
- Error notifications
- Performance metrics

## 🤝 Contributing

1. Follow the TypeScript style guide
2. Add tests for new features
3. Update documentation
4. Run `npm run lint:fix` before committing

## 📄 License

This project is part of the Claude Optimized Deployment Engine and is licensed under the MIT License.

## 🆘 Troubleshooting

### API Key Issues
- Ensure all API keys are correctly set in `config/api_keys.env`
- Run `npm run test:api` to verify connectivity
- Check the logs for specific error messages

### Server Won't Start
- Check if port 3000 is already in use
- Verify Node.js version is 18+
- Check file permissions on the deployment directory

### Build Errors
- Delete `node_modules` and run `npm install` again
- Ensure TypeScript is installed globally: `npm install -g typescript`
- Check for syntax errors in the source files

For more help, check the logs or open an issue in the repository.