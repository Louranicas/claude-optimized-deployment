# MCP Integration Guide

## Overview
The Claude Optimized Deployment project integrates 27 MCP servers.

## Server Inventory

### Core Infrastructure (11 servers)
- Brave Search, Desktop Commander, Docker, Kubernetes
- Azure DevOps, Windows System, Prometheus
- Security Scanner, Slack, S3, Cloud Storage

### Smithery.ai Additions (8 servers)
- desktop-commander (@wonderwhy-er) ✅
- filesystem, postgres, github, memory
- brave-search, slack, puppeteer

### MCP.so Additions (8 servers)
- tavily-mcp, sequential-thinking, redis
- google-maps, gdrive, everything
- vercel-mcp-adapter, smithery-sdk

## Installation
All servers are installed via npm in the `mcp_servers` directory.

## Configuration
Configurations are stored in `mcp_configs/` and auto-loaded by Claude Desktop.

## API Keys Required
- Brave Search: Configured ✅
- Tavily: Required for enhanced search
- Google Maps: Required for location services
- Google OAuth: Required for Drive access
