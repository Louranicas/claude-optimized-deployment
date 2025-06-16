#!/bin/bash

# Script to add all MCP servers to Claude Code

echo "🚀 Adding MCP servers to Claude Code..."

# GitHub server
claude mcp add github npx -- -y @modelcontextprotocol/server-github

# PostgreSQL server
claude mcp add postgres npx -- -y @modelcontextprotocol/server-postgres

# Memory server
claude mcp add memory npx -- -y @modelcontextprotocol/server-memory

# Slack server
claude mcp add slack npx -- -y @modelcontextprotocol/server-slack

# Puppeteer server
claude mcp add puppeteer npx -- -y @modelcontextprotocol/server-puppeteer

# Desktop Commander
claude mcp add desktop-commander npx -- -y @wonderwhy-er/desktop-commander

# Git server
claude mcp add git npx -- -y @modelcontextprotocol/server-git

# SQLite server
claude mcp add sqlite npx -- -y @modelcontextprotocol/server-sqlite --db-path /home/louranicas/projects/claude-optimized-deployment/data/claude.db

# Time server
claude mcp add time npx -- -y @modelcontextprotocol/server-time

# Fetch server
claude mcp add fetch npx -- -y @modelcontextprotocol/server-fetch

# Everything server
claude mcp add everything npx -- -y @modelcontextprotocol/server-everything

# Weather server
claude mcp add weather npx -- -y mcp-server-weather

echo "✅ All MCP servers added!"
echo ""
echo "📋 Listing configured servers:"
claude mcp list