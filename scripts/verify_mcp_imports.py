#!/usr/bin/env python3
"""
MCP Server Import Verification Script
Tests all Python imports in MCP server modules to identify issues
"""

import ast
import importlib
import importlib.util
import os
import sys
import traceback
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any

# Colors for output
class Colors:
    GREEN = '\033[0;32m'
    RED = '\033[0;31m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color

def print_status(message: str):
    print(f"{Colors.GREEN}[INFO]{Colors.NC} {message}")

def print_error(message: str):
    print(f"{Colors.RED}[ERROR]{Colors.NC} {message}")

def print_warning(message: str):
    print(f"{Colors.YELLOW}[WARN]{Colors.NC} {message}")

def print_header(message: str):
    print(f"{Colors.BLUE}[CHECK]{Colors.NC} {message}")

class ImportAnalyzer:
    """Analyzes Python imports in MCP server files"""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.mcp_servers_path = project_root / "mcp_learning_system" / "servers"
        self.all_imports = set()
        self.failed_imports = {}
        self.missing_modules = set()
        self.circular_imports = []
        
    def find_python_files(self) -> List[Path]:
        """Find all Python files in MCP servers directory"""
        python_files = []
        
        for root, dirs, files in os.walk(self.mcp_servers_path):
            # Skip virtual environments and cache directories
            dirs[:] = [d for d in dirs if not d.startswith(('.', '__pycache__', 'venv', 'node_modules'))]
            
            for file in files:
                if file.endswith('.py') and not file.startswith('.'):
                    python_files.append(Path(root) / file)
        
        return python_files
    
    def extract_imports_from_file(self, file_path: Path) -> Tuple[Set[str], Set[str], List[str]]:
        """Extract imports from a Python file using AST"""
        imports = set()
        relative_imports = set()
        errors = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content, filename=str(file_path))
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name)
                        
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ''
                    if node.level > 0:  # Relative import
                        relative_imports.add(f"{'.' * node.level}{module}")
                    else:
                        imports.add(module)
                        
        except SyntaxError as e:
            errors.append(f"Syntax error: {e}")
        except Exception as e:
            errors.append(f"Parse error: {e}")
            
        return imports, relative_imports, errors
    
    def test_import(self, module_name: str) -> Tuple[bool, str]:
        """Test if a module can be imported"""
        if not module_name or module_name.startswith('.'):
            return True, "Relative import (not tested)"
        
        # Skip built-in modules and standard library
        if module_name in sys.builtin_module_names:
            return True, "Built-in module"
        
        try:
            # Try to find the module spec
            spec = importlib.util.find_spec(module_name)
            if spec is None:
                return False, "Module not found"
            
            # Try to import the module
            importlib.import_module(module_name)
            return True, "Success"
            
        except ImportError as e:
            return False, f"Import error: {e}"
        except Exception as e:
            return False, f"Unexpected error: {e}"
    
    def analyze_file(self, file_path: Path) -> Dict[str, Any]:
        """Analyze imports in a single Python file"""
        relative_path = file_path.relative_to(self.project_root)
        
        print_status(f"Analyzing {relative_path}")
        
        # Extract imports
        imports, relative_imports, parse_errors = self.extract_imports_from_file(file_path)
        self.all_imports.update(imports)
        
        # Test imports
        failed_imports = {}
        for module in imports:
            if module:  # Skip empty module names
                success, message = self.test_import(module)
                if not success:
                    failed_imports[module] = message
                    self.missing_modules.add(module)
        
        return {
            'file': str(relative_path),
            'imports': imports,
            'relative_imports': relative_imports,
            'failed_imports': failed_imports,
            'parse_errors': parse_errors,
            'total_imports': len(imports),
            'failed_count': len(failed_imports)
        }
    
    def analyze_all_files(self) -> Dict[str, Any]:
        """Analyze all Python files in MCP servers"""
        print_header("Analyzing MCP Server Python Imports")
        
        python_files = self.find_python_files()
        print_status(f"Found {len(python_files)} Python files")
        
        results = {}
        total_failed = 0
        
        for file_path in python_files:
            try:
                analysis = self.analyze_file(file_path)
                results[str(file_path)] = analysis
                total_failed += analysis['failed_count']
                
                if analysis['parse_errors']:
                    print_error(f"Parse errors in {analysis['file']}: {analysis['parse_errors']}")
                
                if analysis['failed_imports']:
                    print_warning(f"Failed imports in {analysis['file']}: {list(analysis['failed_imports'].keys())}")
                    
            except Exception as e:
                print_error(f"Error analyzing {file_path}: {e}")
                results[str(file_path)] = {
                    'file': str(file_path.relative_to(self.project_root)),
                    'error': str(e),
                    'failed_count': 1
                }
                total_failed += 1
        
        return {
            'files_analyzed': len(python_files),
            'total_imports': len(self.all_imports),
            'missing_modules': list(self.missing_modules),
            'total_failed_imports': total_failed,
            'results': results
        }
    
    def generate_missing_requirements(self) -> List[str]:
        """Generate list of missing packages that should be installed"""
        # Common package mappings
        package_mappings = {
            'sklearn': 'scikit-learn',
            'PIL': 'Pillow',
            'cv2': 'opencv-python',
            'yaml': 'pyyaml',
            'dotenv': 'python-dotenv',
            'jwt': 'pyjwt',
            'redis': 'redis',
            'psutil': 'psutil',
            'paramiko': 'paramiko',
            'fabric': 'fabric',
            'docker': 'docker',
            'kubernetes': 'kubernetes',
            'requests': 'requests',
            'aiohttp': 'aiohttp',
            'websockets': 'websockets',
            'asyncpg': 'asyncpg',
            'aiosqlite': 'aiosqlite',
            'sqlalchemy': 'sqlalchemy',
            'alembic': 'alembic',
            'bandit': 'bandit',
            'pylint': 'pylint',
            'coverage': 'coverage',
            'pytest': 'pytest',
            'click': 'click',
            'rich': 'rich',
            'typer': 'typer',
            'structlog': 'structlog',
            'tenacity': 'tenacity',
            'cachetools': 'cachetools',
            'lru_dict': 'lru-dict',
            'cryptography': 'cryptography',
            'numpy': 'numpy',
            'pandas': 'pandas',
            'joblib': 'joblib',
            'scipy': 'scipy',
        }
        
        missing_packages = []
        for module in self.missing_modules:
            # Get the top-level module name
            top_level = module.split('.')[0]
            
            # Skip standard library modules and our own modules
            if (top_level not in sys.stdlib_module_names and 
                not top_level.startswith('mcp_learning_system') and
                not top_level.startswith('src') and
                top_level not in ['__future__', 'typing_extensions']):
                
                package_name = package_mappings.get(top_level, top_level)
                if package_name not in missing_packages:
                    missing_packages.append(package_name)
        
        return sorted(missing_packages)

def main():
    """Main function"""
    print_header("MCP Server Import Verification")
    
    # Get project root
    script_path = Path(__file__).parent
    project_root = script_path.parent
    
    print_status(f"Project root: {project_root}")
    print_status(f"Python version: {sys.version}")
    print_status(f"Python executable: {sys.executable}")
    
    # Create analyzer
    analyzer = ImportAnalyzer(project_root)
    
    # Check if MCP servers directory exists
    if not analyzer.mcp_servers_path.exists():
        print_error(f"MCP servers directory not found: {analyzer.mcp_servers_path}")
        return 1
    
    # Analyze all files
    results = analyzer.analyze_all_files()
    
    # Print summary
    print_header("Analysis Summary")
    print_status(f"Files analyzed: {results['files_analyzed']}")
    print_status(f"Total unique imports: {results['total_imports']}")
    print_status(f"Failed imports: {results['total_failed_imports']}")
    print_status(f"Missing modules: {len(results['missing_modules'])}")
    
    if results['missing_modules']:
        print_warning("Missing modules:")
        for module in sorted(results['missing_modules']):
            print(f"  - {module}")
    
    # Generate missing requirements
    missing_packages = analyzer.generate_missing_requirements()
    if missing_packages:
        print_header("Recommended packages to install:")
        for package in missing_packages:
            print(f"  pip install {package}")
        
        # Write to requirements file
        missing_req_file = project_root / "requirements-missing.txt"
        with open(missing_req_file, 'w') as f:
            f.write("# Missing packages identified by import analysis\n")
            f.write("# Install with: pip install -r requirements-missing.txt\n\n")
            for package in missing_packages:
                f.write(f"{package}\n")
        
        print_status(f"Missing requirements written to: {missing_req_file}")
    
    # Write detailed results
    import json
    results_file = project_root / "import_analysis_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print_status(f"Detailed results written to: {results_file}")
    
    # Return exit code
    return 1 if results['total_failed_imports'] > 0 else 0

if __name__ == '__main__':
    sys.exit(main())