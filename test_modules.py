#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_module_imports():
    results = {}
    
    modules = [
        ('prometheus', 'mcp.monitoring.prometheus_server', 'PrometheusMonitoringMCP'),
        ('security', 'mcp.security.scanner_server', 'SecurityScannerMCPServer'),
        ('infrastructure', 'mcp.infrastructure.commander_server', 'InfrastructureCommanderMCP'),
        ('storage', 'mcp.storage.cloud_storage_server', 'CloudStorageMCP'),
        ('communication', 'mcp.communication.slack_server', 'SlackNotificationMCPServer')
    ]
    
    for name, module_path, class_name in modules:
        try:
            module = __import__(module_path, fromlist=[class_name])
            cls = getattr(module, class_name)
            results[name] = {'status': 'SUCCESS', 'class': cls}
            print(f"✅ {name}: {class_name} imported successfully")
        except Exception as e:
            results[name] = {'status': 'FAILED', 'error': str(e)}
            print(f"❌ {name}: {e}")
    
    return results

if __name__ == "__main__":
    test_module_imports()