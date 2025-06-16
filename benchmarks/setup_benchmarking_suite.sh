#!/bin/bash
"""
Setup Script for Comprehensive Performance Benchmarking Suite
Sets up the complete benchmarking environment for the CODE project
"""

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_status "🚀 Setting up Comprehensive Performance Benchmarking Suite"
echo "=" * 80

# Check if we're in the right directory
BENCHMARK_DIR="/home/louranicas/projects/claude-optimized-deployment/benchmarks"
if [ ! -d "$BENCHMARK_DIR" ]; then
    print_error "Benchmarks directory not found: $BENCHMARK_DIR"
    exit 1
fi

cd "$BENCHMARK_DIR"
print_status "Working directory: $(pwd)"

# Check Python version
print_status "Checking Python version..."
PYTHON_VERSION=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
    print_error "Python 3.8+ required. Found: Python $PYTHON_VERSION"
    exit 1
fi

print_success "Python $PYTHON_VERSION found"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    print_status "Creating virtual environment..."
    python3 -m venv venv
    print_success "Virtual environment created"
else
    print_status "Virtual environment already exists"
fi

# Activate virtual environment
print_status "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
print_status "Upgrading pip..."
pip install --upgrade pip

# Install requirements
print_status "Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    print_success "Dependencies installed"
else
    print_warning "requirements.txt not found, installing core dependencies..."
    pip install numpy pandas scipy psutil flask flask-socketio plotly requests schedule pytest pytest-asyncio
    print_success "Core dependencies installed"
fi

# Check system dependencies
print_status "Checking system dependencies..."

# Check for Rust (optional but recommended)
if command -v cargo &> /dev/null; then
    print_success "Rust/Cargo found: $(cargo --version)"
else
    print_warning "Rust/Cargo not found - some optimizations will not be available"
    print_status "To install Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
fi

# Check for Git
if command -v git &> /dev/null; then
    print_success "Git found: $(git --version)"
else
    print_warning "Git not found - version tracking may be limited"
fi

# Create necessary directories
print_status "Creating necessary directories..."
mkdir -p logs
mkdir -p reports
mkdir -p data
mkdir -p templates
mkdir -p static

# Set up database
print_status "Setting up performance database..."
python3 -c "
import sys
sys.path.append('.')
from automation_controller import PerformanceDatabase
db = PerformanceDatabase()
print('✅ Database initialized successfully')
"

# Create configuration files
print_status "Creating configuration files..."

# Notification config template
cat > notification_config.json << 'EOF'
{
    "email": {
        "enabled": false,
        "smtp_server": "localhost",
        "smtp_port": 587,
        "username": "",
        "password": "",
        "recipients": []
    },
    "slack": {
        "enabled": false,
        "webhook_url": ""
    }
}
EOF

# Benchmark configuration
cat > benchmark_config.json << 'EOF'
{
    "hardware": {
        "cpu_cores": 16,
        "memory_gb": 32,
        "storage_type": "nvme",
        "gpu_available": true
    },
    "benchmarks": {
        "quick_benchmark_interval_minutes": 360,
        "comprehensive_benchmark_interval_hours": 24,
        "load_testing_enabled": true,
        "optimization_analysis_enabled": true
    },
    "thresholds": {
        "cpu_usage_warning": 80,
        "memory_usage_warning": 75,
        "latency_warning_ms": 1000,
        "error_rate_warning": 5.0
    },
    "dashboard": {
        "host": "0.0.0.0",
        "port": 5000,
        "auto_refresh_seconds": 30
    }
}
EOF

print_success "Configuration files created"

# Create systemd service file (optional)
print_status "Creating systemd service file..."
cat > benchmarking-automation.service << EOF
[Unit]
Description=Performance Benchmarking Automation
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$BENCHMARK_DIR
ExecStart=$BENCHMARK_DIR/venv/bin/python automation_controller.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

print_success "Systemd service file created (benchmarking-automation.service)"
print_status "To enable automation service: sudo cp benchmarking-automation.service /etc/systemd/system/ && sudo systemctl enable benchmarking-automation"

# Create launcher scripts
print_status "Creating launcher scripts..."

# Quick benchmark launcher
cat > run_quick_benchmark.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python3 run_comprehensive_benchmarks.py --mode quick
EOF
chmod +x run_quick_benchmark.sh

# Full benchmark launcher
cat > run_full_benchmark.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python3 run_comprehensive_benchmarks.py --mode full
EOF
chmod +x run_full_benchmark.sh

# Dashboard launcher
cat > start_dashboard.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python3 run_comprehensive_benchmarks.py --mode dashboard --dashboard-host 0.0.0.0
EOF
chmod +x start_dashboard.sh

# Load testing launcher
cat > run_load_testing.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python3 run_comprehensive_benchmarks.py --mode load
EOF
chmod +x run_load_testing.sh

# Optimization analysis launcher
cat > run_optimization_analysis.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python3 run_comprehensive_benchmarks.py --mode optimization
EOF
chmod +x run_optimization_analysis.sh

print_success "Launcher scripts created"

# Test the installation
print_status "Testing installation..."

# Test quick benchmark
print_status "Running installation test..."
python3 -c "
import sys
sys.path.append('.')

# Test imports
try:
    from performance_suite import BenchmarkSuite
    from automation_controller import AutomationController
    from quick_benchmark import QuickBenchmarks
    from load_testing_suite import LoadTestSuite
    from optimization_engine import PerformanceDatabase
    print('✅ All modules imported successfully')
except ImportError as e:
    print(f'❌ Import error: {e}')
    sys.exit(1)

# Test database
try:
    db = PerformanceDatabase()
    print('✅ Database connection successful')
except Exception as e:
    print(f'❌ Database error: {e}')
    sys.exit(1)

print('✅ Installation test passed')
"

if [ $? -eq 0 ]; then
    print_success "Installation test passed!"
else
    print_error "Installation test failed!"
    exit 1
fi

# Create README for the benchmarking suite
print_status "Creating README..."
cat > README_BENCHMARKING.md << 'EOF'
# Comprehensive Performance Benchmarking Suite

This suite provides comprehensive performance testing for the CODE project, optimized for:
- AMD Ryzen 7 7800X3D (8-core, 16-thread)
- 32GB DDR5 6000MHz
- NVMe SSD 2TB
- RX 7900 XT GPU

## Quick Start

### 1. Run Quick Benchmark (5-10 minutes)
```bash
./run_quick_benchmark.sh
```

### 2. Run Full Benchmark Suite (30-60 minutes)
```bash
./run_full_benchmark.sh
```

### 3. Start Performance Dashboard
```bash
./start_dashboard.sh
```
Then open: http://localhost:5000

### 4. Run Load Testing (15-30 minutes)
```bash
./run_load_testing.sh
```

### 5. Run Optimization Analysis
```bash
./run_optimization_analysis.sh
```

## Components

- **Hardware Benchmarks**: CPU, memory, storage, network performance
- **CODE Benchmarks**: Rust compilation, Python FFI, HTM storage, NAM/ANAM validation
- **Load Testing**: Concurrent users, stress testing, failure scenarios
- **Optimization Engine**: AI-driven performance analysis and recommendations
- **Dashboard**: Real-time performance monitoring
- **Automation**: Scheduled benchmarks and regression detection

## Configuration

Edit `benchmark_config.json` to customize:
- Benchmark intervals
- Performance thresholds
- Dashboard settings
- Hardware specifications

Edit `notification_config.json` to set up:
- Email notifications
- Slack integration

## Automation

To enable automated benchmarking:
```bash
sudo cp benchmarking-automation.service /etc/systemd/system/
sudo systemctl enable benchmarking-automation
sudo systemctl start benchmarking-automation
```

## Files Generated

- `*_results_*.json`: Raw benchmark data
- `*_report_*.md`: Human-readable reports  
- `optimization_recommendations_*.json`: Optimization suggestions
- `performance.db`: SQLite database with historical data

## Troubleshooting

1. **Permission Issues**: Ensure user has write access to benchmark directory
2. **Memory Issues**: Reduce test sizes in configuration
3. **Port Conflicts**: Change dashboard port in config
4. **Rust Not Available**: Install Rust for full performance benefits

## Support

For issues or questions, check the generated reports for detailed analysis and recommendations.
EOF

print_success "README created"

# Final summary
echo
echo "=" * 80
print_success "🎉 BENCHMARKING SUITE SETUP COMPLETE!"
echo "=" * 80
echo
print_status "📁 Installation Directory: $BENCHMARK_DIR"
print_status "🐍 Python Environment: $BENCHMARK_DIR/venv"
print_status "📊 Database: $BENCHMARK_DIR/performance.db"
echo
print_status "🚀 QUICK START COMMANDS:"
echo "  ./run_quick_benchmark.sh     # Quick performance test (5-10 min)"
echo "  ./run_full_benchmark.sh      # Complete benchmark suite (30-60 min)"
echo "  ./start_dashboard.sh         # Real-time performance dashboard"
echo "  ./run_load_testing.sh        # Load and stress testing"
echo "  ./run_optimization_analysis.sh  # Performance optimization analysis"
echo
print_status "📖 Documentation: README_BENCHMARKING.md"
print_status "⚙️  Configuration: benchmark_config.json, notification_config.json"
echo
print_warning "💡 RECOMMENDATIONS:"
echo "  1. Run './run_quick_benchmark.sh' to verify installation"
echo "  2. Start dashboard './start_dashboard.sh' for real-time monitoring"  
echo "  3. Schedule full benchmarks using cron or systemd"
echo "  4. Review generated reports for optimization opportunities"
echo
print_success "✅ Ready to benchmark! System optimized for CODE project performance testing."

# Deactivate virtual environment
deactivate 2>/dev/null || true

print_status "Setup complete! 🚀"