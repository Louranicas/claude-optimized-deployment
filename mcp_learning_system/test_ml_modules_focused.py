#!/usr/bin/env python3
"""
AGENT 3: Focused Python ML Module Testing
Testing available Python ML modules with virtual environment.
"""

import sys
import os
import json
import traceback
import subprocess
from typing import Dict, List, Any, Tuple
from datetime import datetime
import importlib.util

# Add paths to Python path
project_root = "/home/louranicas/projects/claude-optimized-deployment/mcp_learning_system"
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "python_learning"))
sys.path.insert(0, os.path.join(project_root, "learning_core"))

class FocusedMLTester:
    """Focused ML module testing with available dependencies"""
    
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "environment_info": {},
            "dependency_check": {},
            "module_structure_analysis": {},
            "available_ml_tests": {},
            "server_module_analysis": {},
            "summary": {}
        }
        
    def check_environment(self) -> Dict[str, Any]:
        """Check Python environment and available packages"""
        print("\n🔧 Checking Environment...")
        
        env_info = {
            "python_version": sys.version,
            "python_executable": sys.executable,
            "working_directory": os.getcwd(),
            "python_path": sys.path[:5]  # First 5 entries
        }
        
        return env_info
    
    def test_core_dependencies(self) -> Dict[str, Any]:
        """Test core ML dependencies that are available"""
        print("\n📦 Testing Core Dependencies...")
        
        dependencies = [
            "numpy", "pandas", "sklearn", "scipy", "matplotlib", 
            "psutil", "json", "os", "sys", "importlib"
        ]
        
        results = {}
        
        for dep in dependencies:
            try:
                if dep == "sklearn":
                    import sklearn
                    results[dep] = {"status": "✅ OK", "version": sklearn.__version__}
                else:
                    module = __import__(dep)
                    version = getattr(module, "__version__", "built-in")
                    results[dep] = {"status": "✅ OK", "version": version}
                    
            except ImportError as e:
                results[dep] = {"status": "❌ MISSING", "error": str(e)}
                
        return results
    
    def analyze_module_structure(self) -> Dict[str, Any]:
        """Analyze the structure of ML modules"""
        print("\n🔍 Analyzing Module Structure...")
        
        results = {}
        
        # Analyze python_learning directory
        python_learning_path = os.path.join(project_root, "python_learning")
        if os.path.exists(python_learning_path):
            results["python_learning"] = self._analyze_directory(python_learning_path)
        
        # Analyze learning_core directory
        learning_core_path = os.path.join(project_root, "learning_core")
        if os.path.exists(learning_core_path):
            results["learning_core"] = self._analyze_directory(learning_core_path)
        
        # Analyze server modules
        servers_path = os.path.join(project_root, "servers")
        if os.path.exists(servers_path):
            results["servers"] = {}
            for server in os.listdir(servers_path):
                server_path = os.path.join(servers_path, server)
                if os.path.isdir(server_path):
                    python_src = os.path.join(server_path, "python_src")
                    if os.path.exists(python_src):
                        results["servers"][server] = self._analyze_directory(python_src)
        
        return results
    
    def _analyze_directory(self, directory_path: str) -> Dict[str, Any]:
        """Analyze a directory for Python files and structure"""
        analysis = {
            "path": directory_path,
            "python_files": [],
            "subdirectories": [],
            "init_file_exists": False,
            "total_files": 0
        }
        
        try:
            for item in os.listdir(directory_path):
                item_path = os.path.join(directory_path, item)
                
                if os.path.isfile(item_path):
                    analysis["total_files"] += 1
                    if item.endswith('.py'):
                        analysis["python_files"].append(item)
                        if item == '__init__.py':
                            analysis["init_file_exists"] = True
                            
                elif os.path.isdir(item_path):
                    analysis["subdirectories"].append(item)
                    
        except Exception as e:
            analysis["error"] = str(e)
            
        return analysis
    
    def test_available_ml_functionality(self) -> Dict[str, Any]:
        """Test ML functionality with available packages"""
        print("\n🧠 Testing Available ML Functionality...")
        
        results = {}
        
        # Test numpy operations
        try:
            import numpy as np
            
            # Basic operations
            test_array = np.random.rand(100, 10)
            mean_val = np.mean(test_array)
            std_val = np.std(test_array)
            
            # Matrix operations
            matrix_a = np.random.rand(50, 50)
            matrix_b = np.random.rand(50, 50)
            matrix_mult = np.dot(matrix_a, matrix_b)
            
            results["numpy_operations"] = {
                "status": "✅ OK",
                "test_array_shape": test_array.shape,
                "mean": float(mean_val),
                "std": float(std_val),
                "matrix_mult_shape": matrix_mult.shape
            }
            
        except Exception as e:
            results["numpy_operations"] = {"status": "❌ FAILED", "error": str(e)}
        
        # Test pandas operations
        try:
            import pandas as pd
            import numpy as np
            
            # Create test DataFrame
            df = pd.DataFrame({
                'A': np.random.randn(1000),
                'B': np.random.randn(1000),
                'C': np.random.choice(['X', 'Y', 'Z'], 1000)
            })
            
            # Basic operations
            summary = df.describe()
            group_stats = df.groupby('C')['A'].mean()
            
            results["pandas_operations"] = {
                "status": "✅ OK",
                "dataframe_shape": df.shape,
                "columns": list(df.columns),
                "group_count": len(group_stats)
            }
            
        except Exception as e:
            results["pandas_operations"] = {"status": "❌ FAILED", "error": str(e)}
        
        # Test scikit-learn operations
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import accuracy_score
            from sklearn.datasets import make_classification
            
            # Generate synthetic dataset
            X, y = make_classification(n_samples=1000, n_features=20, n_classes=2, random_state=42)
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Train model
            clf = RandomForestClassifier(n_estimators=10, random_state=42)
            clf.fit(X_train, y_train)
            
            # Make predictions
            y_pred = clf.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            results["sklearn_ml_pipeline"] = {
                "status": "✅ OK",
                "training_samples": len(X_train),
                "test_samples": len(X_test),
                "features": X.shape[1],
                "accuracy": float(accuracy),
                "model_type": "RandomForestClassifier"
            }
            
        except Exception as e:
            results["sklearn_ml_pipeline"] = {"status": "❌ FAILED", "error": str(e)}
        
        return results
    
    def analyze_server_modules(self) -> Dict[str, Any]:
        """Analyze server-specific ML modules"""
        print("\n🖥️ Analyzing Server ML Modules...")
        
        results = {}
        
        servers = {
            "development": "servers/development/python_src",
            "devops": "servers/devops/python_src", 
            "quality": "servers/quality/python_src",
            "bash_god": "servers/bash_god/python_src"
        }
        
        for server, path in servers.items():
            server_path = os.path.join(project_root, path)
            
            if os.path.exists(server_path):
                # Analyze files in the directory
                analysis = {
                    "path_exists": True,
                    "files": [],
                    "learning_files": [],
                    "import_analysis": {}
                }
                
                try:
                    for file in os.listdir(server_path):
                        if file.endswith('.py'):
                            analysis["files"].append(file)
                            if 'learning' in file.lower():
                                analysis["learning_files"].append(file)
                                
                                # Try to read the file to analyze imports
                                file_path = os.path.join(server_path, file)
                                try:
                                    with open(file_path, 'r') as f:
                                        content = f.read()
                                        
                                    imports = []
                                    for line in content.split('\n'):
                                        line = line.strip()
                                        if line.startswith('import ') or line.startswith('from '):
                                            imports.append(line)
                                    
                                    analysis["import_analysis"][file] = {
                                        "import_count": len(imports),
                                        "imports": imports[:5],  # First 5 imports
                                        "line_count": len(content.split('\n'))
                                    }
                                    
                                except Exception as read_error:
                                    analysis["import_analysis"][file] = {"error": str(read_error)}
                                    
                except Exception as e:
                    analysis["directory_error"] = str(e)
                    
                results[server] = analysis
            else:
                results[server] = {"path_exists": False, "path": server_path}
                
        return results
    
    def test_basic_ml_patterns(self) -> Dict[str, Any]:
        """Test basic ML patterns that can be implemented"""
        print("\n📊 Testing Basic ML Patterns...")
        
        results = {}
        
        try:
            import numpy as np
            from sklearn.cluster import KMeans
            from sklearn.preprocessing import StandardScaler
            
            # Pattern 1: Clustering
            data = np.random.rand(100, 5)
            scaler = StandardScaler()
            scaled_data = scaler.fit_transform(data)
            
            kmeans = KMeans(n_clusters=3, random_state=42, n_init=10)
            clusters = kmeans.fit_predict(scaled_data)
            
            results["clustering_pattern"] = {
                "status": "✅ OK",
                "data_shape": data.shape,
                "n_clusters": 3,
                "unique_clusters": len(np.unique(clusters))
            }
            
        except Exception as e:
            results["clustering_pattern"] = {"status": "❌ FAILED", "error": str(e)}
        
        try:
            # Pattern 2: Anomaly Detection using statistical methods
            import numpy as np
            from scipy import stats
            
            # Generate normal data with some outliers
            normal_data = np.random.normal(0, 1, 1000)
            outliers = np.random.normal(5, 1, 50)
            combined_data = np.concatenate([normal_data, outliers])
            
            # Simple anomaly detection using z-score
            z_scores = np.abs(stats.zscore(combined_data))
            threshold = 3
            anomalies = combined_data[z_scores > threshold]
            
            results["anomaly_detection"] = {
                "status": "✅ OK",
                "total_samples": len(combined_data),
                "detected_anomalies": len(anomalies),
                "threshold": threshold
            }
            
        except Exception as e:
            results["anomaly_detection"] = {"status": "❌ FAILED", "error": str(e)}
        
        return results
    
    def run_comprehensive_test(self) -> Dict[str, Any]:
        """Run comprehensive focused testing"""
        print("🚀 Starting Focused ML Module Testing...")
        print("="*60)
        
        # Run all test categories
        self.results["environment_info"] = self.check_environment()
        self.results["dependency_check"] = self.test_core_dependencies()
        self.results["module_structure_analysis"] = self.analyze_module_structure()
        self.results["available_ml_tests"] = self.test_available_ml_functionality()
        self.results["server_module_analysis"] = self.analyze_server_modules()
        self.results["ml_patterns"] = self.test_basic_ml_patterns()
        
        # Generate summary
        total_tests = 0
        passed_tests = 0
        failed_tests = 0
        
        for category, tests in self.results.items():
            if category in ["timestamp", "summary", "environment_info", "module_structure_analysis", "server_module_analysis"]:
                continue
                
            if isinstance(tests, dict):
                for test_name, result in tests.items():
                    if isinstance(result, dict) and "status" in result:
                        total_tests += 1
                        if result.get("status", "").startswith("✅"):
                            passed_tests += 1
                        else:
                            failed_tests += 1
        
        self.results["summary"] = {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
            "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0,
            "status": "✅ PASSED" if failed_tests == 0 else f"⚠️ {failed_tests} FAILURES"
        }
        
        return self.results
    
    def generate_report(self) -> str:
        """Generate focused test report"""
        report = []
        report.append("# AGENT 3: Focused Python ML Module Testing Report")
        report.append("=" * 60)
        report.append(f"**Test Execution Time**: {self.results['timestamp']}")
        report.append("")
        
        # Summary
        summary = self.results["summary"]
        report.append("## 📊 Executive Summary")
        report.append(f"- **Total Tests**: {summary['total_tests']}")
        report.append(f"- **Passed**: {summary['passed_tests']}")
        report.append(f"- **Failed**: {summary['failed_tests']}")
        report.append(f"- **Success Rate**: {summary['success_rate']:.1f}%")
        report.append(f"- **Overall Status**: {summary['status']}")
        report.append("")
        
        # Environment Info
        if "environment_info" in self.results:
            env = self.results["environment_info"]
            report.append("## 🔧 Environment Information")
            report.append(f"- **Python Version**: {env.get('python_version', 'Unknown')}")
            report.append(f"- **Python Executable**: {env.get('python_executable', 'Unknown')}")
            report.append("")
        
        # Dependency Check
        if "dependency_check" in self.results:
            report.append("## 📦 Core Dependencies")
            for dep, result in self.results["dependency_check"].items():
                status = result.get("status", "Unknown")
                version = result.get("version", "")
                report.append(f"- **{dep}**: {status}")
                if version and version != "built-in":
                    report.append(f"  - Version: {version}")
            report.append("")
        
        # Module Structure Analysis
        if "module_structure_analysis" in self.results:
            report.append("## 🔍 Module Structure Analysis")
            for module, analysis in self.results["module_structure_analysis"].items():
                if isinstance(analysis, dict):
                    report.append(f"### {module}")
                    if "python_files" in analysis:
                        report.append(f"- Python files: {len(analysis['python_files'])}")
                        report.append(f"- Has __init__.py: {analysis.get('init_file_exists', False)}")
                        if analysis["python_files"]:
                            report.append(f"- Files: {', '.join(analysis['python_files'][:5])}")
            report.append("")
        
        # ML Tests
        if "available_ml_tests" in self.results:
            report.append("## 🧠 ML Functionality Tests")
            for test, result in self.results["available_ml_tests"].items():
                status = result.get("status", "Unknown")
                report.append(f"- **{test}**: {status}")
                if "accuracy" in result:
                    report.append(f"  - Accuracy: {result['accuracy']:.3f}")
                if "test_array_shape" in result:
                    report.append(f"  - Array Shape: {result['test_array_shape']}")
            report.append("")
        
        # Server Analysis
        if "server_module_analysis" in self.results:
            report.append("## 🖥️ Server Module Analysis")
            for server, analysis in self.results["server_module_analysis"].items():
                report.append(f"### {server}")
                if analysis.get("path_exists", False):
                    report.append(f"- Files found: {len(analysis.get('files', []))}")
                    report.append(f"- Learning files: {len(analysis.get('learning_files', []))}")
                else:
                    report.append("- Path does not exist")
            report.append("")
        
        return "\n".join(report)

def main():
    """Main test execution"""
    tester = FocusedMLTester()
    
    try:
        # Run comprehensive testing
        results = tester.run_comprehensive_test()
        
        # Generate and save report
        report = tester.generate_report()
        
        # Save results
        results_file = f"/home/louranicas/projects/claude-optimized-deployment/mcp_learning_system/focused_ml_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
            
        # Save report
        report_file = f"/home/louranicas/projects/claude-optimized-deployment/mcp_learning_system/FOCUSED_ML_TEST_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(report_file, 'w') as f:
            f.write(report)
        
        print("\n" + "="*60)
        print("📋 FOCUSED TEST REPORT GENERATED")
        print("="*60)
        print(report)
        
        print(f"\n📄 Results saved to: {results_file}")
        print(f"📄 Report saved to: {report_file}")
        
        return results
        
    except Exception as e:
        print(f"❌ Critical test failure: {e}")
        traceback.print_exc()
        return None

if __name__ == "__main__":
    main()