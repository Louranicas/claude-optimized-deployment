#!/bin/bash

# Setup synergistic MCP servers based on CORE environment analysis
# Priority: High-synergy servers that enhance existing capabilities

echo "🚀 Setting up synergistic MCP servers for CORE environment"
echo "========================================================="

# Function to safely add MCP server
add_mcp() {
    local name=$1
    local package=$2
    echo -n "Adding $name... "
    if claude mcp add "$name" npx -- -y "$package" 2>/dev/null; then
        echo "✅"
    else
        echo "⏭️  (may already exist or not available)"
    fi
}

# Critical Infrastructure Servers
echo -e "\n🏗️ Infrastructure & Deployment"
add_mcp "docker" "@modelcontextprotocol/server-docker"
add_mcp "kubernetes" "@modelcontextprotocol/server-kubernetes"
add_mcp "terraform" "@modelcontextprotocol/server-terraform"
add_mcp "ansible" "@modelcontextprotocol/server-ansible"

# Database & Caching
echo -e "\n💾 Database & Caching"
add_mcp "redis" "@modelcontextprotocol/server-redis"
add_mcp "elasticsearch" "@modelcontextprotocol/server-elasticsearch"
add_mcp "mongodb" "@modelcontextprotocol/server-mongodb"

# Monitoring & Observability
echo -e "\n📊 Monitoring & Observability"
add_mcp "prometheus" "@modelcontextprotocol/server-prometheus"
add_mcp "grafana" "@modelcontextprotocol/server-grafana"
add_mcp "datadog" "@modelcontextprotocol/server-datadog"
add_mcp "sentry" "@modelcontextprotocol/server-sentry"

# Security & Compliance
echo -e "\n🔒 Security & Compliance"
add_mcp "vault" "@modelcontextprotocol/server-vault"
add_mcp "snyk" "@modelcontextprotocol/server-snyk"
add_mcp "trivy" "@modelcontextprotocol/server-trivy"
add_mcp "falco" "@modelcontextprotocol/server-falco"

# AI/ML Operations
echo -e "\n🤖 AI/ML Operations"
add_mcp "openai" "@modelcontextprotocol/server-openai"
add_mcp "anthropic" "@anthropic/mcp-server-anthropic"
add_mcp "huggingface" "@modelcontextprotocol/server-huggingface"
add_mcp "mlflow" "@modelcontextprotocol/server-mlflow"

# Cloud Providers
echo -e "\n☁️ Cloud Providers"
add_mcp "aws" "@modelcontextprotocol/server-aws"
add_mcp "gcp" "@modelcontextprotocol/server-gcp"
add_mcp "azure" "@modelcontextprotocol/server-azure"

# CI/CD & GitOps
echo -e "\n🔄 CI/CD & GitOps"
add_mcp "gitlab" "@modelcontextprotocol/server-gitlab"
add_mcp "jenkins" "@modelcontextprotocol/server-jenkins"
add_mcp "argocd" "@modelcontextprotocol/server-argocd"
add_mcp "flux" "@modelcontextprotocol/server-flux"

# Communication & Collaboration
echo -e "\n💬 Communication"
add_mcp "slack" "npx" "-y" "@modelcontextprotocol/server-slack"
add_mcp "discord" "@modelcontextprotocol/server-discord"
add_mcp "pagerduty" "@modelcontextprotocol/server-pagerduty"

# Development Tools
echo -e "\n🛠️ Development Tools"
add_mcp "sonarqube" "@modelcontextprotocol/server-sonarqube"
add_mcp "jira" "@modelcontextprotocol/server-jira"
add_mcp "confluence" "@modelcontextprotocol/server-confluence"

# Data Processing
echo -e "\n📈 Data Processing"
add_mcp "kafka" "@modelcontextprotocol/server-kafka"
add_mcp "airflow" "@modelcontextprotocol/server-airflow"
add_mcp "spark" "@modelcontextprotocol/server-spark"

# API Management
echo -e "\n🔌 API Management"
add_mcp "swagger" "@modelcontextprotocol/server-swagger"
add_mcp "postman" "@modelcontextprotocol/server-postman"
add_mcp "kong" "@modelcontextprotocol/server-kong"

# Testing Frameworks
echo -e "\n🧪 Testing"
add_mcp "cypress" "@modelcontextprotocol/server-cypress"
add_mcp "selenium" "@modelcontextprotocol/server-selenium"
add_mcp "k6" "@modelcontextprotocol/server-k6"

# Create environment configuration template
echo -e "\n📝 Creating environment configuration template..."
cat > mcp_env_template.sh << 'EOF'
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
EOF

chmod +x mcp_env_template.sh

echo -e "\n📊 Summary"
echo "=========="
claude mcp list | wc -l | xargs echo "Total MCP servers configured:"

echo -e "\n🎯 High-Priority Configurations Needed:"
echo "1. Set cloud provider credentials (AWS, GCP, Azure)"
echo "2. Add AI service API keys (OpenAI, Anthropic)"
echo "3. Configure monitoring tokens (Datadog, Sentry)"
echo "4. Set up communication tokens (Slack, Discord)"
echo ""
echo "📄 Configuration template created: mcp_env_template.sh"
echo "   Copy to .env and fill in your credentials"
echo ""
echo "🔧 To configure with environment variables:"
echo "   source .env"
echo "   claude mcp add <server> <command> -e KEY=\$VALUE"
echo ""
echo "📚 For detailed setup, see: MCP_SETUP_GUIDE.md"