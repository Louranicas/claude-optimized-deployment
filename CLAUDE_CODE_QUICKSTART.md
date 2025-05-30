# CODE Quick Start Guide for Claude Code
[OPTIMIZED FOR CLAUDE CODE USAGE]

## 🚀 What Actually Works Today

### Circle of Experts - Fully Functional ✅

Get expert opinions from multiple AIs with one command:

```python
from src.circle_of_experts import EnhancedExpertManager

# Quick consultation
manager = EnhancedExpertManager()
result = await manager.quick_consult("How to optimize my Python code?")
print(result['recommendations'])
```

### Available Experts
- **Claude** (Opus, Sonnet, Haiku) - Best for complex analysis
- **GPT-4** - Good for general tasks
- **Gemini** - Free tier available
- **Ollama** - Local, free, private
- **Mixtral/Groq** - Fast and affordable

## 🛠️ Setup in 5 Minutes

### 1. Clone and Install

```bash
git clone https://github.com/yourusername/claude_optimized_deployment.git
cd claude_optimized_deployment
pip install -r requirements.txt
```

### 2. Set Up Credentials

Create `.env` file:
```bash
# Required for Circle of Experts
GOOGLE_CREDENTIALS_PATH=/path/to/google-service-account.json

# Add at least one AI provider
ANTHROPIC_API_KEY=your-key-here
# OR
OPENAI_API_KEY=your-key-here
# OR just use Ollama (free)
```

### 3. For Free Local AI (Recommended)

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull models
ollama pull mixtral
ollama pull codellama
```

### 4. Run Setup

```bash
python scripts/setup_circle_of_experts.py
```

## 📋 What You Can Do Today

### 1. Ask Multiple AIs for Advice

```python
# Code review
result = await manager.quick_consult("""
Review this code:
```python
def process_data(items):
    result = []
    for item in items:
        result.append(item * 2)
    return result
```
""")
```

### 2. Compare Expert Opinions

```python
# Get consensus from multiple experts
result = await manager.consult_experts_with_ai(
    title="Architecture Decision",
    content="Should I use microservices or monolith?",
    requester="claude_code",
    min_experts=3,  # Get 3 different opinions
    use_consensus=True
)
```

### 3. Estimate Costs Before Running

```python
# Check costs
costs = await manager.estimate_query_cost(
    "Complex 1000-word technical question",
    expert_count=3
)
print(f"Estimated cost: ${costs['total_estimated']:.4f}")
```

### 4. Use Free Models Only

```python
# Configure free models only
manager = EnhancedExpertManager(
    preferred_experts=["ollama-mixtral", "huggingface", "gemini-pro"]
)
```

## ⚡ Claude Code Integration

### Quick Commands

```python
# One-liner for Claude Code
from src.circle_of_experts import EnhancedExpertManager
result = await EnhancedExpertManager().quick_consult("Your question here")
```

### Best Practices for Claude Code

1. **Use quick_consult() for speed**
2. **Set expert_count=2 for faster responses**
3. **Use Ollama for private/sensitive queries**
4. **Cache results to avoid repeated API calls**

## 🚫 What Doesn't Work Yet

### Not Implemented
- ❌ Actual infrastructure deployment
- ❌ Terraform/Kubernetes integration  
- ❌ Cloud provider connections
- ❌ Natural language to infrastructure

### Coming Soon™
- 🚧 Basic Docker deployment
- 🚧 Simple AWS integration
- 🚧 Authentication system
- 🚧 State management

## 🆘 Troubleshooting

### Common Issues

1. **"No experts available"**
   ```bash
   # Check which APIs are configured
   python -c "import os; print('APIs:', [k for k in os.environ if 'API_KEY' in k])"
   ```

2. **"Google Drive access denied"**
   - Share folders with service account email
   - Check folder IDs in drive/manager.py

3. **"Ollama not responding"**
   ```bash
   # Check if Ollama is running
   curl http://localhost:11434/api/tags
   ```

## 📊 Current Project Reality

- **Working**: Circle of Experts (100%)
- **Not Working**: Everything else (0%)
- **Documentation**: Excellent but aspirational
- **Use Case**: AI consultation only

## 🎯 Recommended Usage

### For Development Help
```python
# Get implementation advice
await manager.quick_consult("""
I need to implement a rate limiter in Python.
Requirements: 100 requests per minute per user
Should work with async code
""")
```

### For Architecture Decisions
```python
# Compare approaches
await manager.quick_consult("""
Compare PostgreSQL vs MongoDB for:
- Time series data
- 1TB+ storage
- Complex queries
""")
```

### For Code Reviews
```python
# Security review
await manager.quick_consult("""
Review this authentication code for security issues:
[paste code here]
""")
```

## 📝 Summary

**What CODE Is Today**: A sophisticated multi-AI consultation system with great documentation

**What CODE Isn't Yet**: A deployment engine (despite the name)

**Best Use**: Getting expert opinions from multiple AIs with consensus building

**Timeline to Deployment Features**: 8-12 weeks minimum

---
*For Claude Code v1.0 - Focus on what works!*
