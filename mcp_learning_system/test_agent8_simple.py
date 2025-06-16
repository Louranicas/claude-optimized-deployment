#!/usr/bin/env python3
"""
AGENT 8 - SIMPLIFIED PRODUCTION INTEGRATION TEST
Testing MCP server claims without external dependencies.
"""

import subprocess
import time
import json
import os
import sys
from pathlib import Path
from datetime import datetime
import psutil
import socket

def test_mcp_docker_services():
    """Test Docker-based MCP services."""
    print("\n[1] Testing Docker MCP Services...")
    
    try:
        # Check docker compose status
        result = subprocess.run(
            ["docker", "compose", "ps", "--format", "json"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent
        )
        
        if result.returncode != 0:
            # Try docker ps instead
            result = subprocess.run(
                ["docker", "ps", "--format", "json"],
                capture_output=True,
                text=True
            )
        
        services_found = []
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        container = json.loads(line)
                        name = container.get('Names', container.get('Name', ''))
                        if 'mcp' in name.lower():
                            services_found.append({
                                'name': name,
                                'status': container.get('State', container.get('Status', 'unknown'))
                            })
                    except json.JSONDecodeError:
                        pass
        
        return {
            'docker_available': result.returncode == 0,
            'services_found': len(services_found),
            'services': services_found
        }
        
    except FileNotFoundError:
        return {
            'docker_available': False,
            'error': 'Docker not installed'
        }

def test_local_services():
    """Test local services on standard ports."""
    print("\n[2] Testing Local Services...")
    
    services = {
        'rust-core': 8080,
        'python-learning': 8000,
        'prometheus': 9090,
        'grafana': 3000,
        'redis': 6379,
        'nginx': 8443
    }
    
    active_services = {}
    
    for service, port in services.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('localhost', port))
        sock.close()
        
        active_services[service] = {
            'port': port,
            'listening': result == 0
        }
    
    return active_services

def test_bash_god_server():
    """Test the Bash God MCP server."""
    print("\n[3] Testing Bash God MCP Server...")
    
    bash_god_path = Path(__file__).parent / "bash_god_mcp_server.py"
    
    if not bash_god_path.exists():
        return {
            'exists': False,
            'error': 'bash_god_mcp_server.py not found'
        }
    
    # Test import and basic functionality
    try:
        # Test if it can be imported
        result = subprocess.run(
            [sys.executable, "-c", f"import sys; sys.path.insert(0, '{bash_god_path.parent}'); from bash_god_mcp_server import BashGodMCPServer"],
            capture_output=True,
            text=True
        )
        
        import_success = result.returncode == 0
        
        # Test command execution
        test_result = subprocess.run(
            [sys.executable, str(bash_god_path), "--test-command", "echo test"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        return {
            'exists': True,
            'import_success': import_success,
            'test_execution': test_result.returncode == 0,
            'output': test_result.stdout[:200] if test_result.stdout else None,
            'error': test_result.stderr[:200] if test_result.stderr else None
        }
        
    except Exception as e:
        return {
            'exists': True,
            'error': str(e)
        }

def test_performance_baseline():
    """Test basic performance metrics."""
    print("\n[4] Testing Performance Metrics...")
    
    # Simple command execution benchmark
    iterations = 100
    
    # Python baseline
    python_start = time.time()
    for _ in range(iterations):
        subprocess.run([sys.executable, "-c", "print('')"], capture_output=True)
    python_duration = time.time() - python_start
    
    # Shell baseline
    shell_start = time.time()
    for _ in range(iterations):
        subprocess.run(["echo", ""], capture_output=True)
    shell_duration = time.time() - shell_start
    
    # Calculate metrics
    python_per_sec = iterations / python_duration
    shell_per_sec = iterations / shell_duration
    
    return {
        'iterations': iterations,
        'python_baseline': {
            'total_seconds': round(python_duration, 3),
            'operations_per_second': round(python_per_sec, 2)
        },
        'shell_baseline': {
            'total_seconds': round(shell_duration, 3),
            'operations_per_second': round(shell_per_sec, 2)
        },
        'improvement_factor': round(shell_per_sec / python_per_sec, 2)
    }

def test_system_resources():
    """Test system resource availability."""
    print("\n[5] Testing System Resources...")
    
    cpu_info = psutil.cpu_freq()
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    return {
        'cpu': {
            'count': psutil.cpu_count(),
            'current_freq_mhz': round(cpu_info.current, 2) if cpu_info else 'N/A',
            'usage_percent': psutil.cpu_percent(interval=1)
        },
        'memory': {
            'total_gb': round(memory.total / (1024**3), 2),
            'available_gb': round(memory.available / (1024**3), 2),
            'usage_percent': memory.percent
        },
        'disk': {
            'total_gb': round(disk.total / (1024**3), 2),
            'free_gb': round(disk.free / (1024**3), 2),
            'usage_percent': disk.percent
        }
    }

def test_mcp_processes():
    """Test for running MCP processes."""
    print("\n[6] Testing MCP Processes...")
    
    mcp_processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline_list = proc.info.get('cmdline', [])
            if cmdline_list and isinstance(cmdline_list, list):
                cmdline = ' '.join(cmdline_list)
            else:
                cmdline = str(cmdline_list)
            if 'mcp' in cmdline.lower():
                mcp_processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'memory_mb': round(proc.memory_info().rss / (1024**2), 2)
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    return {
        'process_count': len(mcp_processes),
        'processes': mcp_processes[:5]  # First 5 processes
    }

def generate_validation_report(results):
    """Generate validation report based on test results."""
    
    # Count operational items
    docker_services = results['docker_services']['services_found']
    local_services = sum(1 for s in results['local_services'].values() if s.get('listening'))
    mcp_processes = results['mcp_processes']['process_count']
    bash_god_ready = results['bash_god_server'].get('import_success', False)
    
    total_operational = docker_services + local_services + mcp_processes
    
    # Performance check
    perf_factor = results['performance']['improvement_factor']
    
    # Generate findings
    findings = []
    
    if total_operational < 10:
        findings.append(f"Only {total_operational} MCP-related services found (expected 10)")
    
    if perf_factor < 100:
        findings.append(f"Performance improvement only {perf_factor}x (claimed 539x)")
    
    if not bash_god_ready:
        findings.append("Bash God MCP server not operational")
    
    # API check (simplified)
    api_ready = os.getenv('TAVILY_API_KEY') is not None or os.getenv('BRAVE_API_KEY') is not None
    if not api_ready:
        findings.append("No API keys configured for Tavily/Brave")
    
    return {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_services_found': total_operational,
            'docker_services': docker_services,
            'local_services': local_services,
            'mcp_processes': mcp_processes,
            'performance_factor': perf_factor,
            'bash_god_operational': bash_god_ready,
            'api_keys_configured': api_ready
        },
        'validation_results': {
            'mcp_servers_operational': {
                'claim': '10/10 servers',
                'actual': f'{total_operational}/10',
                'validated': total_operational >= 10
            },
            'performance_improvement': {
                'claim': '539x',
                'actual': f'{perf_factor}x',
                'validated': perf_factor >= 100
            },
            'bash_command_processing': {
                'claim': 'Real bash processing',
                'actual': bash_god_ready,
                'validated': bash_god_ready
            },
            'api_integration': {
                'claim': '100% operational',
                'actual': '0%' if not api_ready else 'Keys configured',
                'validated': api_ready
            }
        },
        'critical_findings': findings if findings else ['All basic checks passed'],
        'raw_results': results
    }

def main():
    """Run all tests and generate report."""
    print("="*70)
    print("AGENT 8 - SIMPLIFIED PRODUCTION INTEGRATION TEST")
    print("="*70)
    
    results = {}
    
    # Run all tests
    results['docker_services'] = test_mcp_docker_services()
    results['local_services'] = test_local_services()
    results['bash_god_server'] = test_bash_god_server()
    results['performance'] = test_performance_baseline()
    results['system_resources'] = test_system_resources()
    results['mcp_processes'] = test_mcp_processes()
    
    # Generate report
    report = generate_validation_report(results)
    
    # Save report
    report_path = f"agent8_integration_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    print("\n" + "="*70)
    print("VALIDATION SUMMARY")
    print("="*70)
    
    for claim, result in report['validation_results'].items():
        status = "✓" if result['validated'] else "✗"
        print(f"\n{status} {claim}")
        print(f"  Claim: {result['claim']}")
        print(f"  Actual: {result['actual']}")
    
    print("\nCRITICAL FINDINGS:")
    for finding in report['critical_findings']:
        print(f"• {finding}")
    
    print(f"\n✓ Report saved to: {report_path}")
    
    # Return exit code based on validation
    validated_count = sum(1 for r in report['validation_results'].values() if r['validated'])
    total_claims = len(report['validation_results'])
    
    if validated_count == total_claims:
        return 0
    elif validated_count >= total_claims / 2:
        return 1
    else:
        return 2

if __name__ == "__main__":
    sys.exit(main())