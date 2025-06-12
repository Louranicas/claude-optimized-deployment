#!/usr/bin/env python3
"""
Memory usage analysis script for dependency optimization.

This script analyzes memory usage of dependencies to help optimize the
dependency footprint and identify memory-heavy packages.

Features:
- Import-time memory measurement
- Dependency size analysis
- Memory usage comparison between installation methods
- CI/CD integration for dependency bloat detection
- Memory profiling and recommendations

Usage:
    python scripts/analyze_memory_usage.py --analyze-imports
    python scripts/analyze_memory_usage.py --compare-installations
    python scripts/analyze_memory_usage.py --profile-dependencies
    python scripts/analyze_memory_usage.py --ci-check --memory-limit 500
"""

import argparse
import json
import os
import subprocess
import sys
import time
import tracemalloc
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MemoryAnalyzer:
    """Analyzes memory usage of Python dependencies."""
    
    def __init__(self, project_root: Optional[Path] = None):
        """Initialize the memory analyzer."""
        self.project_root = project_root or Path(__file__).parent.parent
        self.results = {}
        
    def analyze_import_memory(self, modules: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Analyze memory usage of importing specific modules.
        
        Args:
            modules: List of module names to analyze
            
        Returns:
            Dictionary with memory usage results for each module
        """
        results = {}
        
        for module_name in modules:
            logger.info(f"Analyzing memory usage for {module_name}")
            
            # Measure import memory in isolation
            memory_usage = self._measure_import_memory(module_name)
            results[module_name] = memory_usage
            
        return results
    
    def _measure_import_memory(self, module_name: str) -> Dict[str, Any]:
        """Measure memory usage of importing a single module."""
        # Create a subprocess to measure import memory in isolation
        script = f'''
import tracemalloc
import time
import sys

tracemalloc.start()
start_time = time.time()

try:
    import {module_name}
    import_success = True
    error_message = None
except Exception as e:
    import_success = False
    error_message = str(e)

end_time = time.time()
current, peak = tracemalloc.get_traced_memory()
tracemalloc.stop()

result = {{
    "import_success": import_success,
    "error_message": error_message,
    "memory_current_bytes": current,
    "memory_peak_bytes": peak,
    "memory_current_mb": current / (1024 * 1024),
    "memory_peak_mb": peak / (1024 * 1024),
    "import_time_seconds": end_time - start_time,
    "module_name": "{module_name}"
}}

import json
print(json.dumps(result))
'''
        
        try:
            result = subprocess.run(
                [sys.executable, '-c', script],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                return json.loads(result.stdout.strip())
            else:
                logger.error(f"Failed to analyze {module_name}: {result.stderr}")
                return {
                    "import_success": False,
                    "error_message": result.stderr,
                    "memory_current_bytes": 0,
                    "memory_peak_bytes": 0,
                    "memory_current_mb": 0,
                    "memory_peak_mb": 0,
                    "import_time_seconds": 0,
                    "module_name": module_name
                }
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout analyzing {module_name}")
            return {
                "import_success": False,
                "error_message": "Import timeout",
                "memory_current_bytes": 0,
                "memory_peak_bytes": 0,
                "memory_current_mb": 0,
                "memory_peak_mb": 0,
                "import_time_seconds": 60,
                "module_name": module_name
            }
    
    def analyze_installation_sizes(self) -> Dict[str, Any]:
        """Analyze installed package sizes."""
        try:
            # Get package sizes using pip show
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'list', '--format=json'],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to get package list: {result.stderr}")
                return {}
            
            packages = json.loads(result.stdout)
            package_sizes = {}
            
            for package in packages:
                name = package['name']
                version = package['version']
                
                # Get package location and size
                size_info = self._get_package_size(name)
                package_sizes[name] = {
                    'version': version,
                    'size_bytes': size_info.get('size_bytes', 0),
                    'size_mb': size_info.get('size_bytes', 0) / (1024 * 1024),
                    'location': size_info.get('location', ''),
                    'files_count': size_info.get('files_count', 0)
                }
            
            return package_sizes
            
        except Exception as e:
            logger.error(f"Failed to analyze installation sizes: {e}")
            return {}
    
    def _get_package_size(self, package_name: str) -> Dict[str, Any]:
        """Get the disk size of an installed package."""
        try:
            # Get package info
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'show', '-f', package_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                return {'size_bytes': 0, 'location': '', 'files_count': 0}
            
            lines = result.stdout.split('\n')
            location = ''
            files = []
            
            # Parse pip show output
            in_files_section = False
            for line in lines:
                if line.startswith('Location:'):
                    location = line.split(':', 1)[1].strip()
                elif line.startswith('Files:'):
                    in_files_section = True
                elif in_files_section and line.strip():
                    if not line.startswith(' '):
                        break
                    files.append(line.strip())
            
            # Calculate total size
            total_size = 0
            if location and files:
                package_path = Path(location)
                for file_path in files:
                    try:
                        full_path = package_path / file_path
                        if full_path.exists():
                            total_size += full_path.stat().st_size
                    except (OSError, FileNotFoundError):
                        pass
            
            return {
                'size_bytes': total_size,
                'location': location,
                'files_count': len(files)
            }
            
        except Exception as e:
            logger.debug(f"Failed to get size for {package_name}: {e}")
            return {'size_bytes': 0, 'location': '', 'files_count': 0}
    
    def compare_installation_methods(self) -> Dict[str, Any]:
        """
        Compare memory usage between different installation methods.
        
        Compares:
        - Core installation (requirements.txt)
        - Full installation with all extras
        - Individual extras
        """
        comparison = {
            'methods': {},
            'recommendations': []
        }
        
        # Test core installation
        core_modules = [
            'pydantic', 'fastapi', 'httpx', 'sqlalchemy', 
            'click', 'rich', 'structlog'
        ]
        
        comparison['methods']['core'] = {
            'description': 'Core installation (minimal)',
            'modules': core_modules,
            'memory_analysis': self.analyze_import_memory(core_modules)
        }
        
        # Test heavy AI modules (if available)
        ai_modules = ['transformers', 'langchain', 'torch', 'ollama']
        available_ai = []
        for module in ai_modules:
            try:
                __import__(module)
                available_ai.append(module)
            except ImportError:
                pass
        
        if available_ai:
            comparison['methods']['ai'] = {
                'description': 'AI/ML modules (heavy)',
                'modules': available_ai,
                'memory_analysis': self.analyze_import_memory(available_ai)
            }
        
        # Test cloud modules (if available)
        cloud_modules = ['boto3', 'azure.mgmt', 'google.cloud']
        available_cloud = []
        for module in cloud_modules:
            try:
                __import__(module)
                available_cloud.append(module)
            except ImportError:
                pass
        
        if available_cloud:
            comparison['methods']['cloud'] = {
                'description': 'Cloud SDK modules (heavy)',
                'modules': available_cloud,
                'memory_analysis': self.analyze_import_memory(available_cloud)
            }
        
        # Calculate totals and generate recommendations
        for method, data in comparison['methods'].items():
            total_memory = sum(
                result.get('memory_peak_mb', 0) 
                for result in data['memory_analysis'].values()
                if result.get('import_success', False)
            )
            data['total_memory_mb'] = total_memory
        
        # Generate recommendations
        core_memory = comparison['methods']['core']['total_memory_mb']
        
        if 'ai' in comparison['methods']:
            ai_memory = comparison['methods']['ai']['total_memory_mb']
            if ai_memory > core_memory * 2:
                comparison['recommendations'].append(
                    f"AI modules use {ai_memory:.1f}MB vs {core_memory:.1f}MB for core. "
                    "Consider using lazy imports or optional extras."
                )
        
        return comparison
    
    def check_dependency_bloat(self, memory_limit_mb: int = 500) -> Dict[str, Any]:
        """
        Check for dependency bloat and provide CI/CD-friendly results.
        
        Args:
            memory_limit_mb: Memory limit for CI/CD check
            
        Returns:
            Dictionary with bloat analysis and pass/fail status
        """
        logger.info(f"Checking dependency bloat with limit {memory_limit_mb}MB")
        
        # Analyze current installation
        package_sizes = self.analyze_installation_sizes()
        
        # Calculate total size
        total_size_mb = sum(
            info.get('size_mb', 0) for info in package_sizes.values()
        )
        
        # Find largest packages
        large_packages = [
            {'name': name, 'size_mb': info['size_mb']}
            for name, info in package_sizes.items()
            if info.get('size_mb', 0) > 10  # Packages larger than 10MB
        ]
        large_packages.sort(key=lambda x: x['size_mb'], reverse=True)
        
        # Check for known heavy packages
        heavy_packages = [
            'torch', 'tensorflow', 'transformers', 'langchain',
            'numpy', 'pandas', 'scipy', 'opencv-python',
            'boto3', 'azure-mgmt', 'google-cloud-storage'
        ]
        
        found_heavy = [
            name for name in package_sizes.keys()
            if any(heavy in name.lower() for heavy in heavy_packages)
        ]
        
        # Determine pass/fail status
        passed = total_size_mb <= memory_limit_mb
        
        result = {
            'passed': passed,
            'total_size_mb': total_size_mb,
            'memory_limit_mb': memory_limit_mb,
            'package_count': len(package_sizes),
            'large_packages': large_packages[:10],  # Top 10 largest
            'heavy_packages_found': found_heavy,
            'recommendations': []
        }
        
        # Generate recommendations
        if not passed:
            result['recommendations'].append(
                f"Total dependency size ({total_size_mb:.1f}MB) exceeds "
                f"limit ({memory_limit_mb}MB)"
            )
        
        if found_heavy:
            result['recommendations'].append(
                f"Heavy packages detected: {', '.join(found_heavy[:5])}. "
                "Consider using optional extras or lazy imports."
            )
        
        if large_packages:
            top_package = large_packages[0]
            result['recommendations'].append(
                f"Largest package: {top_package['name']} "
                f"({top_package['size_mb']:.1f}MB)"
            )
        
        return result
    
    def generate_report(self, output_file: Optional[str] = None) -> Dict[str, Any]:
        """Generate a comprehensive dependency memory report."""
        logger.info("Generating comprehensive dependency memory report")
        
        report = {
            'timestamp': time.time(),
            'project_root': str(self.project_root),
            'analysis_results': {}
        }
        
        # Installation size analysis
        logger.info("Analyzing installation sizes...")
        report['analysis_results']['installation_sizes'] = self.analyze_installation_sizes()
        
        # Installation method comparison
        logger.info("Comparing installation methods...")
        report['analysis_results']['method_comparison'] = self.compare_installation_methods()
        
        # Dependency bloat check
        logger.info("Checking for dependency bloat...")
        report['analysis_results']['bloat_check'] = self.check_dependency_bloat()
        
        # Summary statistics
        sizes = report['analysis_results']['installation_sizes']
        total_size = sum(info.get('size_mb', 0) for info in sizes.values())
        
        report['summary'] = {
            'total_packages': len(sizes),
            'total_size_mb': total_size,
            'average_package_size_mb': total_size / len(sizes) if sizes else 0,
            'largest_packages': sorted(
                [
                    {'name': name, 'size_mb': info['size_mb']}
                    for name, info in sizes.items()
                ],
                key=lambda x: x['size_mb'],
                reverse=True
            )[:5]
        }
        
        # Save report if output file specified
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report saved to {output_file}")
        
        return report


def main():
    """Main function for CLI usage."""
    parser = argparse.ArgumentParser(
        description="Analyze memory usage of Python dependencies"
    )
    
    parser.add_argument(
        '--analyze-imports',
        action='store_true',
        help='Analyze import-time memory usage'
    )
    
    parser.add_argument(
        '--compare-installations',
        action='store_true',
        help='Compare different installation methods'
    )
    
    parser.add_argument(
        '--profile-dependencies',
        action='store_true',
        help='Profile all dependencies'
    )
    
    parser.add_argument(
        '--ci-check',
        action='store_true',
        help='Run CI/CD dependency bloat check'
    )
    
    parser.add_argument(
        '--memory-limit',
        type=int,
        default=500,
        help='Memory limit in MB for CI check (default: 500)'
    )
    
    parser.add_argument(
        '--modules',
        nargs='+',
        help='Specific modules to analyze'
    )
    
    parser.add_argument(
        '--output',
        help='Output file for report (JSON format)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    analyzer = MemoryAnalyzer()
    
    try:
        if args.analyze_imports:
            modules = args.modules or [
                'pydantic', 'fastapi', 'httpx', 'sqlalchemy',
                'transformers', 'langchain', 'boto3'
            ]
            results = analyzer.analyze_import_memory(modules)
            print(json.dumps(results, indent=2))
            
        elif args.compare_installations:
            results = analyzer.compare_installation_methods()
            print(json.dumps(results, indent=2))
            
        elif args.profile_dependencies:
            report = analyzer.generate_report(args.output)
            if not args.output:
                print(json.dumps(report, indent=2))
                
        elif args.ci_check:
            results = analyzer.check_dependency_bloat(args.memory_limit)
            print(json.dumps(results, indent=2))
            
            # Exit with error code if check failed
            if not results['passed']:
                logger.error("Dependency bloat check failed!")
                for rec in results['recommendations']:
                    logger.error(f"  - {rec}")
                sys.exit(1)
            else:
                logger.info("Dependency bloat check passed!")
                
        else:
            # Default: generate full report
            report = analyzer.generate_report(args.output)
            if not args.output:
                print(json.dumps(report, indent=2))
    
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()