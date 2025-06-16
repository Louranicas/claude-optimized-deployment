#!/bin/bash

# Add CORE-synergistic MCP servers to Claude Code
# Based on ai_docs analysis and project requirements

echo "🚀 Adding CORE-synergistic MCP servers..."
echo "=================================="

# Function to add MCP server with error handling
add_mcp_server() {
    local name=$1
    local command=$2
    shift 2
    local args="$@"
    
    echo "Adding $name..."
    if claude mcp add "$name" $command -- $args; then
        echo "✅ $name added successfully"
    else
        echo "❌ Failed to add $name"
    fi
}

# Critical Infrastructure Servers
echo -e "\n📦 Adding Infrastructure Servers..."
add_mcp_server "docker" "npx" "-y" "@modelcontextprotocol/server-docker"
add_mcp_server "kubernetes" "npx" "-y" "@modelcontextprotocol/server-kubernetes"
add_mcp_server "terraform" "npx" "-y" "@modelcontextprotocol/server-terraform"

# Database and Storage Servers
echo -e "\n💾 Adding Database/Storage Servers..."
add_mcp_server "redis" "npx" "-y" "@modelcontextprotocol/server-redis"
add_mcp_server "mongodb" "npx" "-y" "@modelcontextprotocol/server-mongodb"
add_mcp_server "s3" "npx" "-y" "@modelcontextprotocol/server-s3"

# Monitoring and Observability
echo -e "\n📊 Adding Monitoring Servers..."
add_mcp_server "prometheus" "npx" "-y" "@modelcontextprotocol/server-prometheus"
add_mcp_server "grafana" "npx" "-y" "@modelcontextprotocol/server-grafana"
add_mcp_server "datadog" "npx" "-y" "@modelcontextprotocol/server-datadog"

# Security Servers
echo -e "\n🔒 Adding Security Servers..."
add_mcp_server "vault" "npx" "-y" "@modelcontextprotocol/server-vault"
add_mcp_server "security-scanner" "npx" "-y" "@modelcontextprotocol/server-security-scanner"
add_mcp_server "sast" "npx" "-y" "@modelcontextprotocol/server-sast"

# AI/ML Operations
echo -e "\n🤖 Adding AI/ML Servers..."
add_mcp_server "mlflow" "npx" "-y" "@modelcontextprotocol/server-mlflow"
add_mcp_server "wandb" "npx" "-y" "@modelcontextprotocol/server-wandb"
add_mcp_server "huggingface" "npx" "-y" "@modelcontextprotocol/server-huggingface"

# Communication and Collaboration
echo -e "\n💬 Adding Communication Servers..."
add_mcp_server "discord" "npx" "-y" "@modelcontextprotocol/server-discord"
add_mcp_server "teams" "npx" "-y" "@modelcontextprotocol/server-teams"
add_mcp_server "jira" "npx" "-y" "@modelcontextprotocol/server-jira"

# Development Tools
echo -e "\n🛠️ Adding Development Tool Servers..."
add_mcp_server "vscode" "npx" "-y" "@modelcontextprotocol/server-vscode"
add_mcp_server "jupyter" "npx" "-y" "@modelcontextprotocol/server-jupyter"
add_mcp_server "gitlab" "npx" "-y" "@modelcontextprotocol/server-gitlab"

# Cloud Provider Integrations
echo -e "\n☁️ Adding Cloud Provider Servers..."
add_mcp_server "aws" "npx" "-y" "@modelcontextprotocol/server-aws"
add_mcp_server "gcp" "npx" "-y" "@modelcontextprotocol/server-gcp"
add_mcp_server "azure" "npx" "-y" "@modelcontextprotocol/server-azure"

# Analytics and Data Processing
echo -e "\n📈 Adding Analytics Servers..."
add_mcp_server "elasticsearch" "npx" "-y" "@modelcontextprotocol/server-elasticsearch"
add_mcp_server "kafka" "npx" "-y" "@modelcontextprotocol/server-kafka"
add_mcp_server "spark" "npx" "-y" "@modelcontextprotocol/server-spark"

# Testing and Quality
echo -e "\n🧪 Adding Testing Servers..."
add_mcp_server "cypress" "npx" "-y" "@modelcontextprotocol/server-cypress"
add_mcp_server "selenium" "npx" "-y" "@modelcontextprotocol/server-selenium"
add_mcp_server "sonarqube" "npx" "-y" "@modelcontextprotocol/server-sonarqube"

# Deployment and CI/CD
echo -e "\n🚢 Adding Deployment Servers..."
add_mcp_server "jenkins" "npx" "-y" "@modelcontextprotocol/server-jenkins"
add_mcp_server "circleci" "npx" "-y" "@modelcontextprotocol/server-circleci"
add_mcp_server "argocd" "npx" "-y" "@modelcontextprotocol/server-argocd"

# API and Integration
echo -e "\n🔌 Adding API/Integration Servers..."
add_mcp_server "postman" "npx" "-y" "@modelcontextprotocol/server-postman"
add_mcp_server "swagger" "npx" "-y" "@modelcontextprotocol/server-swagger"
add_mcp_server "webhook" "npx" "-y" "@modelcontextprotocol/server-webhook"

# Documentation and Knowledge
echo -e "\n📚 Adding Documentation Servers..."
add_mcp_server "confluence" "npx" "-y" "@modelcontextprotocol/server-confluence"
add_mcp_server "notion" "npx" "-y" "@modelcontextprotocol/server-notion"
add_mcp_server "obsidian" "npx" "-y" "@modelcontextprotocol/server-obsidian"

echo -e "\n✅ MCP Server addition complete!"
echo "=================================="
echo ""
echo "📋 Listing all configured servers:"
claude mcp list | head -50
echo ""
echo "💡 Note: Some servers may require additional configuration:"
echo "- API keys for cloud providers (AWS, GCP, Azure)"
echo "- Authentication tokens for services (Slack, Discord, Teams)"
echo "- Connection strings for databases"
echo ""
echo "📖 For configuration help, see: MCP_SETUP_GUIDE.md"