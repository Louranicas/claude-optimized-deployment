#!/bin/bash
# MCP Environment Configuration Template
# Copy to .env and fill in your values

# Cloud Providers
export AWS_ACCESS_KEY_ID=""
export AWS_SECRET_ACCESS_KEY=""
export AWS_DEFAULT_REGION="us-east-1"

export GOOGLE_APPLICATION_CREDENTIALS=""
export GCP_PROJECT_ID=""

export AZURE_SUBSCRIPTION_ID=""
export AZURE_TENANT_ID=""
export AZURE_CLIENT_ID=""
export AZURE_CLIENT_SECRET=""

# AI/ML Services
export OPENAI_API_KEY=""
export ANTHROPIC_API_KEY=""
export HUGGINGFACE_TOKEN=""

# Monitoring
export DATADOG_API_KEY=""
export DATADOG_APP_KEY=""
export SENTRY_DSN=""

# Security
export VAULT_ADDR=""
export VAULT_TOKEN=""
export SNYK_TOKEN=""

# Communication
export SLACK_BOT_TOKEN=""
export DISCORD_BOT_TOKEN=""
export PAGERDUTY_API_KEY=""

# Databases
export REDIS_URL="redis://localhost:6379"
export MONGODB_URI="mongodb://localhost:27017"
export ELASTICSEARCH_URL="http://localhost:9200"

# Version Control
export GITHUB_TOKEN=""
export GITLAB_TOKEN=""

# CI/CD
export JENKINS_URL=""
export JENKINS_USER=""
export JENKINS_TOKEN=""

# Project Management
export JIRA_URL=""
export JIRA_EMAIL=""
export JIRA_API_TOKEN=""
