# Circle of Experts - API Requirements and Setup Guide

## Overview

The Circle of Experts feature integrates multiple AI models and open source alternatives to provide comprehensive analysis and recommendations. This document lists all API requirements and setup instructions for each expert system.

## Required API Keys and Credentials

### 1. Google Drive API (Required)
- **Purpose**: File storage and synchronization for queries/responses
- **Setup**:
  1. Go to [Google Cloud Console](https://console.cloud.google.com)
  2. Create a new project or select existing
  3. Enable Google Drive API
  4. Create Service Account credentials
  5. Download JSON credentials file
  6. Share folders with service account email:
     - Queries folder: `1ob-NYNWMXaE3oiyPzRAk2-VpNbMvfFMS`
     - Responses folder: `1YWh7lD1x8z8HrF-1FS6qPCw64ZQwvUHv`

### 2. Anthropic Claude API (Recommended)
- **Purpose**: Claude expert responses
- **Models**: Claude 3 Opus, Claude 3 Sonnet, Claude 3 Haiku
- **Setup**:
  1. Sign up at [Anthropic Console](https://console.anthropic.com)
  2. Generate API key
  3. Set environment variable: `ANTHROPIC_API_KEY`
- **Pricing**: Pay-per-use, see [pricing](https://www.anthropic.com/pricing)
- **Rate Limits**: Varies by tier

### 3. OpenAI API (Optional)
- **Purpose**: GPT-4 expert responses
- **Models**: GPT-4, GPT-4-Turbo, GPT-3.5-Turbo
- **Setup**:
  1. Sign up at [OpenAI Platform](https://platform.openai.com)
  2. Generate API key
  3. Set environment variable: `OPENAI_API_KEY`
- **Pricing**: Pay-per-token
- **Rate Limits**: Based on usage tier

### 4. Google Gemini API (Optional)
- **Purpose**: Gemini Pro expert responses
- **Models**: Gemini Pro, Gemini Pro Vision
- **Setup**:
  1. Get API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
  2. Set environment variable: `GOOGLE_GEMINI_API_KEY`
- **Pricing**: Free tier available, then pay-per-use
- **Rate Limits**: 60 requests per minute (free tier)

### 5. Groq API (Optional - Supergrok)
- **Purpose**: Fast inference with open models
- **Models**: Mixtral, Llama 2, and others
- **Setup**:
  1. Sign up at [Groq Cloud](https://console.groq.com)
  2. Generate API key
  3. Set environment variable: `GROQ_API_KEY`
- **Pricing**: Pay-per-token
- **Rate Limits**: Based on model

## Open Source Alternatives (No API Key Required)

### 1. Ollama (Recommended for Local LLMs)
- **Purpose**: Run LLMs locally
- **Models**: Llama 2, Mistral, Mixtral, CodeLlama, and more
- **Setup**:
  ```bash
  # Install Ollama
  curl -fsSL https://ollama.ai/install.sh | sh
  
  # Pull models
  ollama pull mistral
  ollama pull codellama
  ollama pull mixtral
  ollama pull llama2
  ```
- **Resource Requirements**: 8GB+ RAM for 7B models, 16GB+ for 13B models

### 2. LocalAI (OpenAI-Compatible Local API)
- **Purpose**: Drop-in replacement for OpenAI API
- **Setup**:
  ```bash
  # Using Docker
  docker run -p 8080:8080 -v $PWD/models:/models \
    -ti --rm quay.io/go-skynet/local-ai:latest
  ```
- **Models**: Any GGML/GGUF compatible model

### 3. LM Studio (GUI-based Local LLMs)
- **Purpose**: Easy local model management
- **Download**: [LM Studio](https://lmstudio.ai/)
- **Features**: Model downloading, quantization, API server

### 4. Text Generation WebUI (Advanced Users)
- **Purpose**: Comprehensive local LLM interface
- **Setup**:
  ```bash
  git clone https://github.com/oobabooga/text-generation-webui
  cd text-generation-webui
  pip install -r requirements.txt
  python server.py --api
  ```

### 5. vLLM (High-Performance Inference)
- **Purpose**: Fast local inference server
- **Setup**:
  ```bash
  pip install vllm
  python -m vllm.entrypoints.api_server \
    --model mistralai/Mistral-7B-Instruct-v0.1
  ```

### 6. Hugging Face Inference API (Free Tier)
- **Purpose**: Access to thousands of models
- **Setup**:
  1. Create account at [Hugging Face](https://huggingface.co)
  2. Generate token
  3. Set environment variable: `HUGGINGFACE_API_TOKEN`
- **Free Tier**: Limited requests per hour

## Environment Variables Summary

Create a `.env` file in your project root:

```bash
# Required
GOOGLE_CREDENTIALS_PATH=/path/to/google-service-account.json

# Commercial APIs (at least one recommended)
ANTHROPIC_API_KEY=your_anthropic_key
OPENAI_API_KEY=your_openai_key
GOOGLE_GEMINI_API_KEY=your_gemini_key
GROQ_API_KEY=your_groq_key

# Open Source APIs
HUGGINGFACE_API_TOKEN=your_hf_token
OLLAMA_HOST=http://localhost:11434  # Default Ollama endpoint
LOCALAI_HOST=http://localhost:8080  # Default LocalAI endpoint

# Circle of Experts Configuration
CIRCLE_OF_EXPERTS_QUERIES_FOLDER=1ob-NYNWMXaE3oiyPzRAk2-VpNbMvfFMS
CIRCLE_OF_EXPERTS_RESPONSES_FOLDER=1YWh7lD1x8z8HrF-1FS6qPCw64ZQwvUHv

# Optional Configuration
EXPERT_RESPONSE_TIMEOUT=300  # Seconds to wait for responses
MIN_EXPERT_RESPONSES=2       # Minimum responses before consensus
LOG_LEVEL=INFO
```

## Cost Optimization Strategies

### 1. Tiered Approach
- Use open source models (Ollama) for initial analysis
- Escalate to commercial APIs for complex queries
- Use Claude 3 Haiku or GPT-3.5-Turbo for cost-effective responses

### 2. Caching Strategy
- Cache common query patterns
- Store expert responses for reuse
- Implement semantic similarity matching

### 3. Model Selection
- Small models for classification/routing
- Medium models for general queries
- Large models for complex analysis

## Setup Priority

1. **Essential**: Google Drive API (for file storage)
2. **Primary Expert**: Either Anthropic Claude OR Ollama (local)
3. **Secondary Experts**: Add 1-2 more for consensus
4. **Optional**: Additional experts for specialized domains

## Quick Start Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Set up credentials
export GOOGLE_CREDENTIALS_PATH=/path/to/credentials.json
export ANTHROPIC_API_KEY=your_key

# For local models (recommended)
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull mistral
ollama pull codellama

# Run setup script
python scripts/setup_circle_of_experts.py

# Test the system
python examples/circle_of_experts_usage.py
```

## Monitoring and Debugging

### Check API Status
```python
from src.circle_of_experts.experts import ExpertHealthCheck

# Check all configured experts
health = ExpertHealthCheck()
status = await health.check_all_experts()
print(status)
```

### Debug Mode
```bash
export LOG_LEVEL=DEBUG
export CIRCLE_OF_EXPERTS_DEBUG=true
```

## Security Considerations

1. **API Keys**: Never commit API keys to version control
2. **Rate Limiting**: Implement backoff strategies
3. **Cost Controls**: Set spending limits on commercial APIs
4. **Data Privacy**: Use local models for sensitive data
5. **Access Control**: Restrict Google Drive folder permissions

## Troubleshooting

### Common Issues

1. **Google Drive Access Denied**
   - Ensure service account has Editor access to both folders
   - Check folder IDs are correct

2. **API Rate Limits**
   - Implement exponential backoff
   - Use multiple API keys with rotation
   - Consider local alternatives

3. **Local Model Performance**
   - Ensure adequate RAM/VRAM
   - Use quantized models for better performance
   - Consider GPU acceleration

4. **Network Timeouts**
   - Increase `EXPERT_RESPONSE_TIMEOUT`
   - Check firewall settings
   - Use local models for offline capability

## Support

- Documentation: See `src/circle_of_experts/README.md`
- Examples: Check `examples/circle_of_experts_usage.py`
- Issues: Create issue in project repository
