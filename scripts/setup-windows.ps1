# Windows Setup Script for Claude-Optimized Deployment Engine
# Run this in PowerShell as Administrator

Write-Host "===================================" -ForegroundColor Cyan
Write-Host "CODE Windows Environment Setup" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Host "This script requires Administrator privileges. Please run as Administrator." -ForegroundColor Red
    exit 1
}

# Enable WSL if not already enabled
Write-Host "`n📦 Checking WSL installation..." -ForegroundColor Yellow

$wslStatus = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
if ($wslStatus.State -ne "Enabled") {
    Write-Host "  Installing WSL..." -ForegroundColor Green
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
    Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
    Write-Host "  ✓ WSL features enabled (restart required)" -ForegroundColor Green
} else {
    Write-Host "  ✓ WSL already enabled" -ForegroundColor Green
}

# Install WSL2 if not present
Write-Host "`n🐧 Setting up WSL2..." -ForegroundColor Yellow
try {
    wsl --set-default-version 2
    Write-Host "  ✓ WSL2 set as default" -ForegroundColor Green
} catch {
    Write-Host "  Installing WSL2 kernel update..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi -OutFile wsl_update_x64.msi
    Start-Process msiexec.exe -Wait -ArgumentList '/I wsl_update_x64.msi /quiet'
    Remove-Item wsl_update_x64.msi
    wsl --set-default-version 2
}

# Install Ubuntu for WSL if not present
$distros = wsl -l -q
if ($distros -notcontains "Ubuntu") {
    Write-Host "`n🐧 Installing Ubuntu for WSL..." -ForegroundColor Yellow
    wsl --install -d Ubuntu
    Write-Host "  ✓ Ubuntu installed" -ForegroundColor Green
} else {
    Write-Host "`n✓ Ubuntu already installed" -ForegroundColor Green
}

# Install Chocolatey if not present
Write-Host "`n🍫 Setting up Chocolatey package manager..." -ForegroundColor Yellow
if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    Write-Host "  ✓ Chocolatey installed" -ForegroundColor Green
} else {
    Write-Host "  ✓ Chocolatey already installed" -ForegroundColor Green
}

# Install essential Windows tools
Write-Host "`n🔧 Installing essential tools..." -ForegroundColor Yellow

$tools = @(
    @{name="git"; package="git"},
    @{name="code"; package="vscode"},
    @{name="docker"; package="docker-desktop"},
    @{name="python"; package="python"},
    @{name="node"; package="nodejs"},
    @{name="terraform"; package="terraform"},
    @{name="kubectl"; package="kubernetes-cli"},
    @{name="helm"; package="kubernetes-helm"},
    @{name="gh"; package="gh"}
)

foreach ($tool in $tools) {
    if (!(Get-Command $tool.name -ErrorAction SilentlyContinue)) {
        Write-Host "  Installing $($tool.name)..." -ForegroundColor White
        choco install $tool.package -y --no-progress
    } else {
        Write-Host "  ✓ $($tool.name) already installed" -ForegroundColor Green
    }
}

# Configure Git for Windows
Write-Host "`n📝 Configuring Git..." -ForegroundColor Yellow
git config --global core.autocrlf true
git config --global core.eol lf
Write-Host "  ✓ Git configured for cross-platform development" -ForegroundColor Green

# Install VS Code extensions for Claude Code
Write-Host "`n🎨 Installing VS Code extensions..." -ForegroundColor Yellow

$extensions = @(
    "ms-vscode-remote.remote-wsl",
    "ms-vscode-remote.remote-containers",
    "ms-python.python",
    "ms-python.vscode-pylance",
    "ms-kubernetes-tools.vscode-kubernetes-tools",
    "hashicorp.terraform",
    "redhat.vscode-yaml",
    "GitHub.copilot",
    "GitHub.copilot-chat",
    "ms-azuretools.vscode-docker",
    "eamodio.gitlens"
)

foreach ($ext in $extensions) {
    Write-Host "  Installing $ext..." -ForegroundColor White
    code --install-extension $ext --force
}
Write-Host "  ✓ VS Code extensions installed" -ForegroundColor Green

# Create project directories
Write-Host "`n📁 Creating project structure..." -ForegroundColor Yellow

$projectRoot = "$env:USERPROFILE\Desktop\My Programming\claude_optimized_deployment"
$directories = @(
    ".claude",
    ".claude\context",
    "src\core",
    "src\providers",
    "src\nlp",
    "src\api",
    "src\platform",
    "infrastructure\terraform",
    "infrastructure\kubernetes",
    "infrastructure\helm",
    "models",
    "configs"
)

foreach ($dir in $directories) {
    $path = Join-Path $projectRoot $dir
    if (!(Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        Write-Host "  Created $dir" -ForegroundColor White
    }
}
Write-Host "  ✓ Project structure created" -ForegroundColor Green

# Create Claude Code configuration
Write-Host "`n🤖 Creating Claude Code configuration..." -ForegroundColor Yellow

$claudeConfig = @"
{
  "name": "Claude-Optimized Deployment Engine",
  "type": "infrastructure-automation",
  "version": "0.1.0",
  "context": {
    "primaryLanguage": "python",
    "frameworks": ["fastapi", "kubernetes", "terraform"],
    "platforms": ["linux", "wsl", "windows"],
    "aiModels": ["claude-3.5-sonnet", "gpt-4", "local-ollama"]
  },
  "features": {
    "naturalLanguageDeployment": true,
    "multiCloudSupport": ["aws", "azure", "gcp"],
    "openSourceFirst": true,
    "wslIntegration": true
  },
  "commands": {
    "deploy": "Natural language deployment command",
    "analyze": "Analyze infrastructure costs and performance",
    "secure": "Run security audit on infrastructure",
    "optimize": "Optimize resource allocation"
  },
  "preferences": {
    "explainComplexity": true,
    "includeTests": true,
    "documentationStyle": "comprehensive",
    "errorHandling": "detailed",
    "parallelExecution": true
  }
}
"@

$claudeConfig | Out-File -FilePath "$projectRoot\.claude\project.json" -Encoding UTF8
Write-Host "  ✓ Claude configuration created" -ForegroundColor Green

# Create Windows Terminal profile for CODE
Write-Host "`n🖥️ Configuring Windows Terminal..." -ForegroundColor Yellow

$terminalSettingsPath = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
if (Test-Path $terminalSettingsPath) {
    Write-Host "  Added CODE profile to Windows Terminal" -ForegroundColor Green
    # Note: Manual configuration recommended to avoid breaking existing settings
} else {
    Write-Host "  Windows Terminal not found, skipping configuration" -ForegroundColor Yellow
}

# Create PowerShell profile with CODE helpers
Write-Host "`n🚀 Setting up PowerShell profile..." -ForegroundColor Yellow

$profileContent = @'

# CODE PowerShell Helpers

# Quick navigation
function code-project { Set-Location "$env:USERPROFILE\Desktop\My Programming\claude_optimized_deployment" }
Set-Alias -Name cdcode -Value code-project

# WSL helpers
function Enter-WSL { wsl -d Ubuntu }
function Run-InWSL { param($Command) wsl -d Ubuntu -e bash -c $Command }

# Claude Code commands
function Invoke-CodeDeploy {
    param([string]$Description)
    Run-InWSL "claude-code deploy '$Description'"
}

function Invoke-CodeAnalyze {
    Run-InWSL "claude-code analyze"
}

function Invoke-CodeSecure {
    Run-InWSL "claude-code secure"
}

# Aliases
Set-Alias -Name code-deploy -Value Invoke-CodeDeploy
Set-Alias -Name code-analyze -Value Invoke-CodeAnalyze
Set-Alias -Name code-secure -Value Invoke-CodeSecure

# Docker helpers
function Start-DockerDesktop {
    Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
}

# Kubernetes helpers
function Get-KubePods { kubectl get pods --all-namespaces }
Set-Alias -Name kpods -Value Get-KubePods

Write-Host "CODE helpers loaded. Use 'code-deploy', 'code-analyze', 'code-secure'" -ForegroundColor Cyan
'@

if (!(Test-Path $PROFILE)) {
    New-Item -ItemType File -Path $PROFILE -Force | Out-Null
}
Add-Content -Path $PROFILE -Value $profileContent
Write-Host "  ✓ PowerShell profile updated" -ForegroundColor Green

# Create batch file for easy access
Write-Host "`n🎯 Creating quick access scripts..." -ForegroundColor Yellow

$batchContent = @"
@echo off
echo Starting CODE Development Environment...
cd /d "%USERPROFILE%\Desktop\My Programming\claude_optimized_deployment"
wsl -d Ubuntu -e bash -c "cd ~/code-workspace && source ~/code-env/bin/activate && exec bash"
"@

$batchContent | Out-File -FilePath "$projectRoot\start-code.bat" -Encoding ASCII
Write-Host "  ✓ Created start-code.bat" -ForegroundColor Green

# Performance optimizations
Write-Host "`n⚡ Applying performance optimizations..." -ForegroundColor Yellow

# Exclude project directory from Windows Defender
Add-MpPreference -ExclusionPath $projectRoot
Write-Host "  ✓ Added Windows Defender exclusion" -ForegroundColor Green

# Configure WSL memory limits
$wslConfig = @"
[wsl2]
memory=8GB
processors=4
swap=4GB
localhostForwarding=true
nestedVirtualization=true

[experimental]
sparseVhd=true
autoMemoryReclaim=gradual
"@

$wslConfig | Out-File -FilePath "$env:USERPROFILE\.wslconfig" -Encoding UTF8
Write-Host "  ✓ WSL configuration optimized" -ForegroundColor Green

# Final message
Write-Host "`n✅ Windows Setup Complete!" -ForegroundColor Green
Write-Host "===================================" -ForegroundColor Cyan
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Restart your computer to complete WSL installation"
Write-Host "2. Open Ubuntu from Start Menu and complete initial setup"
Write-Host "3. Run setup-wsl.sh inside Ubuntu: ./scripts/setup-wsl.sh"
Write-Host "4. Start development: .\start-code.bat"
Write-Host ""
Write-Host "Quick commands:" -ForegroundColor Yellow
Write-Host "- code-deploy 'description' - Deploy using natural language"
Write-Host "- code-analyze - Analyze infrastructure"
Write-Host "- code-secure - Run security audit"
Write-Host "- cdcode - Navigate to project directory"
Write-Host "===================================" -ForegroundColor Cyan
