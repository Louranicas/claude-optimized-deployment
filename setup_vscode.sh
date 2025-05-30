#!/bin/bash
# Setup Script for VS Code and Virtual Environment
# For CODE Project - Bash version

echo "🚀 Setting up CODE project for VS Code..."

# Navigate to project directory
cd "C:/Users/luke_/Desktop/My Programming/claude_optimized_deployment" || exit

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python -m venv venv
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/Scripts/activate

# Upgrade pip
echo "📈 Upgrading pip..."
python -m pip install --upgrade pip

# Install dependencies
echo "📚 Installing project dependencies..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
fi
if [ -f "requirements-dev.txt" ]; then
    pip install -r requirements-dev.txt
fi

# Install additional development tools
echo "🛠️ Installing development tools..."
pip install black flake8 mypy pytest pytest-asyncio pytest-cov safety detect-secrets isort

# Install Claude Code
echo "🤖 Installing Claude Code..."
pip install claude-code

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        echo "⚙️ Creating .env file from template..."
        cp .env.example .env
        echo "⚠️  Please edit .env file with your API keys"
    fi
fi

# Set up Git hooks
echo "🪝 Setting up Git hooks..."
if [ -f "scripts/git/setup-hooks.sh" ]; then
    chmod +x scripts/git/*.sh
    ./scripts/git/setup-hooks.sh
fi

# Install VS Code extensions
echo "📦 Installing VS Code extensions..."
extensions=(
    "ms-python.python"
    "ms-python.vscode-pylance"
    "ms-python.black-formatter"
    "eamodio.gitlens"
    "yzhang.markdown-all-in-one"
    "gruntfuggly.todo-tree"
    "streetsidesoftware.code-spell-checker"
    "continue.continue"
)

for ext in "${extensions[@]}"; do
    code --install-extension "$ext"
done

# Open VS Code
echo "🎨 Opening VS Code..."
code .

echo ""
echo "✨ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit .env file with your API keys"
echo "2. In VS Code, select Python interpreter: Ctrl+Shift+P -> 'Python: Select Interpreter'"
echo "3. Choose: ./venv/Scripts/python.exe"
echo "4. Test with: python examples/circle_of_experts_usage.py"
echo ""
echo "Quick commands:"
echo "  Run tests: Ctrl+Shift+T"
echo "  Format code: Ctrl+Shift+F"
echo "  Run task: Ctrl+Shift+P -> 'Tasks: Run Task'"
