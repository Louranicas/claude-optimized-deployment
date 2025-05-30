# Setup Script for VS Code and Virtual Environment
# For CODE Project

Write-Output "Setting up CODE project for VS Code..."

# Check if we're in the right directory
$projectPath = "C:\Users\luke_\Desktop\My Programming\claude_optimized_deployment"
if ((Get-Location).Path -ne $projectPath) {
    Set-Location $projectPath
}

# Create virtual environment if it doesn't exist
if (-not (Test-Path "venv")) {
    Write-Output "Creating virtual environment..."
    python -m venv venv
} else {
    Write-Output "Virtual environment already exists"
}

# Activate virtual environment
Write-Output "Activating virtual environment..."
& ".\venv\Scripts\Activate.ps1"

# Upgrade pip
Write-Output "Upgrading pip..."
python -m pip install --upgrade pip

# Install dependencies
Write-Output "Installing project dependencies..."
if (Test-Path "requirements.txt") {
    pip install -r requirements.txt
}
if (Test-Path "requirements-dev.txt") {
    pip install -r requirements-dev.txt
}

# Install additional development tools
Write-Output "Installing development tools..."
pip install black flake8 mypy pytest pytest-asyncio pytest-cov safety detect-secrets isort

# Install Claude Code
Write-Output "Installing Claude Code..."
pip install claude-code

# Create .env file if it doesn't exist
if (-not (Test-Path ".env")) {
    if (Test-Path ".env.example") {
        Write-Output "Creating .env file from template..."
        Copy-Item ".env.example" ".env"
        Write-Output "Please edit .env file with your API keys"
    }
}

# Set up Git hooks
Write-Output "Setting up Git hooks..."
if (Test-Path "scripts\git\setup-hooks.sh") {
    bash scripts/git/setup-hooks.sh
}

# Install VS Code extensions
Write-Output "Installing VS Code extensions..."
$extensions = @(
    "ms-python.python",
    "ms-python.vscode-pylance",
    "ms-python.black-formatter",
    "eamodio.gitlens",
    "yzhang.markdown-all-in-one",
    "gruntfuggly.todo-tree",
    "streetsidesoftware.code-spell-checker",
    "continue.continue"
)

foreach ($ext in $extensions) {
    code --install-extension $ext
}

# Open VS Code
Write-Output "Opening VS Code..."
code .

Write-Output ""
Write-Output "Setup complete!"
Write-Output ""
Write-Output "Next steps:"
Write-Output "1. Edit .env file with your API keys"
Write-Output "2. In VS Code, select Python interpreter: Ctrl+Shift+P -> Python: Select Interpreter"
Write-Output "3. Choose: .\venv\Scripts\python.exe"
Write-Output "4. Test with: python examples\circle_of_experts_usage.py"
Write-Output ""
Write-Output "Quick commands:"
Write-Output "  Run tests: Ctrl+Shift+T"
Write-Output "  Format code: Ctrl+Shift+F"
Write-Output "  Run task: Ctrl+Shift+P -> Tasks: Run Task"
