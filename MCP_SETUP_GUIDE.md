# MCP (Model Context Protocol) Setup Guide for Claude Code

## Overview

MCP (Model Context Protocol) allows Claude Code to integrate with external services and tools through standardized server interfaces. This guide will help you configure MCP servers for your Claude Code environment.

## Quick Setup

### 1. Check Current Configuration
```bash
claude mcp
```

### 2. Create MCP Configuration File

Claude Code looks for MCP configuration in `~/.config/claude/mcp.json` (Linux/Mac) or `%APPDATA%\claude\mcp.json` (Windows).

### 3. Basic Configuration Structure

```json
{
  "mcpServers": {
    "server-name": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-name"],
      "env": {
        "API_KEY": "your-api-key-here"
      }
    }
  }
}
```

## Available MCP Servers

Based on your project's configuration, here are the available MCP servers:

### 1. **Filesystem Server**
Provides file system access capabilities.
```json
"filesystem": {
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-filesystem"],
  "env": {}
}
```

### 2. **Brave Search Server**
Enables web search through Brave Search API.
```json
"brave-search": {
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-brave-search"],
  "env": {
    "BRAVE_API_KEY": "your-brave-api-key"
  }
}
```

### 3. **GitHub Server**
Integrates with GitHub repositories.
```json
"github": {
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-github"],
  "env": {
    "GITHUB_TOKEN": "your-github-token"
  }
}
```

### 4. **PostgreSQL Server**
Connects to PostgreSQL databases.
```json
"postgres": {
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-postgres"],
  "env": {
    "POSTGRES_URL": "postgresql://user:password@localhost/dbname"
  }
}
```

### 5. **Memory Server**
Provides persistent memory storage.
```json
"memory": {
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-memory"],
  "env": {}
}
```

### 6. **Slack Server**
Integrates with Slack workspaces.
```json
"slack": {
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-slack"],
  "env": {
    "SLACK_BOT_TOKEN": "xoxb-your-token"
  }
}
```

### 7. **Puppeteer Server**
Enables web automation and scraping.
```json
"puppeteer": {
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-puppeteer"],
  "env": {}
}
```

## Complete Example Configuration

Create `~/.config/claude/mcp.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem"],
      "env": {}
    },
    "brave-search": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-brave-search"],
      "env": {
        "BRAVE_API_KEY": "your-api-key-here"
      }
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_your_token_here"
      }
    }
  }
}
```

## Setup Steps

1. **Create the configuration directory**:
   ```bash
   mkdir -p ~/.config/claude
   ```

2. **Create the MCP configuration file**:
   ```bash
   nano ~/.config/claude/mcp.json
   ```

3. **Add your configuration** (use the example above)

4. **Restart Claude Code** to load the new configuration

5. **Verify configuration**:
   ```bash
   claude mcp
   ```

## API Keys and Authentication

### Getting API Keys:

1. **Brave Search API**: 
   - Visit https://api.search.brave.com/
   - Sign up for a free account
   - Generate an API key

2. **GitHub Token**:
   - Go to GitHub Settings > Developer settings > Personal access tokens
   - Generate a new token with required permissions

3. **Slack Bot Token**:
   - Create a Slack app at https://api.slack.com/apps
   - Install to workspace and get bot token

## Troubleshooting

### Common Issues:

1. **"No MCP servers configured"**
   - Ensure `mcp.json` exists in the correct location
   - Check file permissions
   - Verify JSON syntax

2. **Server fails to start**
   - Check that Node.js is installed: `node --version`
   - Verify network connectivity
   - Check API key validity

3. **Permission errors**
   - Update `.claude/settings.local.json` with required permissions
   - Restart Claude Code after changes

## Advanced Configuration

### Custom MCP Servers

Your project includes custom MCP servers in `src/mcp/`:
- Infrastructure Commander Server
- DevOps Servers
- Monitoring Servers
- Security Servers

To use these, you'll need to build and configure them locally.

### Environment-Specific Configuration

You can use different configurations for different environments:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/allowed/directory"],
      "env": {}
    }
  }
}
```

## Security Best Practices

1. **Never commit API keys** to version control
2. **Use environment variables** for sensitive data
3. **Limit filesystem access** to specific directories
4. **Regularly rotate API keys**
5. **Monitor MCP server logs** for suspicious activity

## Next Steps

1. Configure the MCP servers you need
2. Test each server individually
3. Check the project's MCP integration examples in `examples/`
4. Review custom MCP servers in `src/mcp/`

For more information, visit the official MCP documentation or check the project's MCP integration guide.