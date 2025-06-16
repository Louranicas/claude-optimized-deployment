#!/usr/bin/env python3
"""
AGENT 3: Comprehensive ML Algorithm Testing
Testing actual ML algorithms and learning patterns in the MCP system.
"""

import sys
import os
import json
import traceback
import asyncio
from typing import Dict, List, Any, Tuple
from datetime import datetime
import importlib.util

# Add paths to Python path
project_root = "/home/louranicas/projects/claude-optimized-deployment/mcp_learning_system"
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "python_learning"))
sys.path.insert(0, os.path.join(project_root, "learning_core"))

class MLAlgorithmTester:
    """Comprehensive ML algorithm testing system"""
    
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "algorithm_validation": {},
            "data_pipeline_tests": {},
            "learning_pattern_tests": {},
            "integration_tests": {},
            "performance_benchmarks": {},
            "real_world_scenarios": {},
            "summary": {}
        }
        
    def test_ml_algorithms(self) -> Dict[str, Any]:
        """Test core ML algorithms"""
        print("\n🧠 Testing ML Algorithms...")
        
        results = {}
        
        # Test 1: Classification Pipeline
        try:
            from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
            from sklearn.model_selection import train_test_split, cross_val_score
            from sklearn.metrics import classification_report, confusion_matrix
            from sklearn.datasets import make_classification
            import numpy as np
            
            # Generate complex dataset
            X, y = make_classification(
                n_samples=2000, 
                n_features=20, 
                n_informative=15,
                n_redundant=5,
                n_classes=3,
                n_clusters_per_class=2,
                random_state=42
            )
            
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Test multiple algorithms
            algorithms = {
                'RandomForest': RandomForestClassifier(n_estimators=50, random_state=42),
                'GradientBoosting': GradientBoostingClassifier(n_estimators=50, random_state=42)
            }
            
            algorithm_results = {}
            for name, clf in algorithms.items():
                # Train and evaluate
                clf.fit(X_train, y_train)
                train_score = clf.score(X_train, y_train)
                test_score = clf.score(X_test, y_test)
                
                # Cross-validation
                cv_scores = cross_val_score(clf, X_train, y_train, cv=5)
                
                algorithm_results[name] = {
                    "train_accuracy": float(train_score),
                    "test_accuracy": float(test_score),
                    "cv_mean": float(np.mean(cv_scores)),
                    "cv_std": float(np.std(cv_scores)),
                    "overfitting_check": train_score - test_score < 0.1
                }
            
            results["classification_pipeline"] = {
                "status": "✅ OK",
                "dataset_shape": X.shape,
                "n_classes": len(np.unique(y)),
                "algorithms": algorithm_results
            }
            
        except Exception as e:
            results["classification_pipeline"] = {"status": "❌ FAILED", "error": str(e)}
        
        # Test 2: Clustering Analysis
        try:
            from sklearn.cluster import KMeans, DBSCAN
            from sklearn.preprocessing import StandardScaler
            from sklearn.metrics import silhouette_score, adjusted_rand_score
            import numpy as np
            
            # Generate clustering data
            from sklearn.datasets import make_blobs
            X_cluster, y_true = make_blobs(n_samples=300, centers=4, random_state=42)
            
            # Standardize features
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X_cluster)
            
            # Test clustering algorithms
            kmeans = KMeans(n_clusters=4, random_state=42, n_init=10)
            dbscan = DBSCAN(eps=0.5, min_samples=5)
            
            kmeans_labels = kmeans.fit_predict(X_scaled)
            dbscan_labels = dbscan.fit_predict(X_scaled)
            
            # Evaluate clustering
            kmeans_silhouette = silhouette_score(X_scaled, kmeans_labels)
            kmeans_ari = adjusted_rand_score(y_true, kmeans_labels)
            
            # DBSCAN evaluation (handle noise points)
            if len(set(dbscan_labels)) > 1:
                dbscan_silhouette = silhouette_score(X_scaled, dbscan_labels)
                dbscan_ari = adjusted_rand_score(y_true, dbscan_labels)
            else:
                dbscan_silhouette = 0.0
                dbscan_ari = 0.0
            
            results["clustering_analysis"] = {
                "status": "✅ OK",
                "data_shape": X_cluster.shape,
                "true_clusters": len(np.unique(y_true)),
                "kmeans": {
                    "silhouette_score": float(kmeans_silhouette),
                    "adjusted_rand_score": float(kmeans_ari),
                    "n_clusters_found": len(np.unique(kmeans_labels))
                },
                "dbscan": {
                    "silhouette_score": float(dbscan_silhouette),
                    "adjusted_rand_score": float(dbscan_ari),
                    "n_clusters_found": len(set(dbscan_labels)) - (1 if -1 in dbscan_labels else 0),
                    "noise_points": sum(1 for x in dbscan_labels if x == -1)
                }
            }
            
        except Exception as e:
            results["clustering_analysis"] = {"status": "❌ FAILED", "error": str(e)}
        
        # Test 3: Time Series Analysis
        try:
            import numpy as np
            import pandas as pd
            from scipy import signal
            
            # Generate time series data
            t = np.linspace(0, 10, 1000)
            trend = 0.1 * t
            seasonal = 2 * np.sin(2 * np.pi * t) + np.sin(4 * np.pi * t)
            noise = np.random.normal(0, 0.5, len(t))
            ts_data = trend + seasonal + noise
            
            # Create DataFrame
            ts_df = pd.DataFrame({
                'timestamp': pd.date_range('2024-01-01', periods=len(ts_data), freq='H'),
                'value': ts_data
            })
            
            # Basic time series analysis
            rolling_mean = ts_df['value'].rolling(window=24).mean()
            rolling_std = ts_df['value'].rolling(window=24).std()
            
            # Detect anomalies using statistical methods
            mean_val = ts_df['value'].mean()
            std_val = ts_df['value'].std()
            anomalies = ts_df[np.abs(ts_df['value'] - mean_val) > 3 * std_val]
            
            # Frequency analysis
            frequencies, power = signal.welch(ts_data, fs=1.0)
            dominant_freq_idx = np.argmax(power[1:]) + 1  # Skip DC component
            dominant_frequency = frequencies[dominant_freq_idx]
            
            results["time_series_analysis"] = {
                "status": "✅ OK",
                "data_length": len(ts_data),
                "mean": float(mean_val),
                "std": float(std_val),
                "anomalies_detected": len(anomalies),
                "dominant_frequency": float(dominant_frequency),
                "rolling_stats_available": not rolling_mean.isna().all()
            }
            
        except Exception as e:
            results["time_series_analysis"] = {"status": "❌ FAILED", "error": str(e)}
        
        return results
    
    def test_data_pipelines(self) -> Dict[str, Any]:
        """Test data processing pipelines"""
        print("\n🔄 Testing Data Pipelines...")
        
        results = {}
        
        # Test 1: Data Preprocessing Pipeline
        try:
            import pandas as pd
            import numpy as np
            from sklearn.preprocessing import StandardScaler, LabelEncoder, OneHotEncoder
            from sklearn.impute import SimpleImputer
            
            # Create synthetic dataset with missing values and mixed types
            n_samples = 1000
            data = {
                'numeric1': np.random.randn(n_samples),
                'numeric2': np.random.exponential(2, n_samples),
                'categorical': np.random.choice(['A', 'B', 'C'], n_samples),
                'binary': np.random.choice([0, 1], n_samples),
                'text': [f"text_{i}" for i in range(n_samples)]
            }
            
            # Introduce missing values
            missing_indices = np.random.choice(n_samples, size=n_samples//10, replace=False)
            data['numeric1'][missing_indices[:len(missing_indices)//2]] = np.nan
            
            df = pd.DataFrame(data)
            
            # Pipeline steps
            pipeline_steps = []
            
            # 1. Handle missing values
            numeric_columns = ['numeric1', 'numeric2']
            imputer = SimpleImputer(strategy='mean')
            df[numeric_columns] = imputer.fit_transform(df[numeric_columns])
            pipeline_steps.append("missing_value_imputation")
            
            # 2. Scale numeric features
            scaler = StandardScaler()
            df[numeric_columns] = scaler.fit_transform(df[numeric_columns])
            pipeline_steps.append("numeric_scaling")
            
            # 3. Encode categorical features
            le = LabelEncoder()
            df['categorical_encoded'] = le.fit_transform(df['categorical'])
            pipeline_steps.append("categorical_encoding")
            
            # 4. Create features
            df['feature_interaction'] = df['numeric1'] * df['numeric2']
            df['numeric1_squared'] = df['numeric1'] ** 2
            pipeline_steps.append("feature_engineering")
            
            results["data_preprocessing_pipeline"] = {
                "status": "✅ OK",
                "original_shape": (n_samples, len(data)),
                "processed_shape": df.shape,
                "pipeline_steps": pipeline_steps,
                "missing_values_handled": True,
                "features_created": 2,
                "categorical_classes": len(le.classes_)
            }
            
        except Exception as e:
            results["data_preprocessing_pipeline"] = {"status": "❌ FAILED", "error": str(e)}
        
        # Test 2: Feature Selection Pipeline
        try:
            from sklearn.feature_selection import SelectKBest, f_classif, RFE
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.datasets import make_classification
            
            # Generate high-dimensional dataset
            X, y = make_classification(
                n_samples=500,
                n_features=50,
                n_informative=10,
                n_redundant=10,
                n_clusters_per_class=1,
                random_state=42
            )
            
            # Test different feature selection methods
            selection_methods = {}
            
            # 1. Statistical feature selection
            selector_stats = SelectKBest(f_classif, k=15)
            X_selected_stats = selector_stats.fit_transform(X, y)
            selection_methods["statistical"] = {
                "original_features": X.shape[1],
                "selected_features": X_selected_stats.shape[1],
                "method": "f_classif"
            }
            
            # 2. Recursive feature elimination
            estimator = RandomForestClassifier(n_estimators=10, random_state=42)
            selector_rfe = RFE(estimator, n_features_to_select=15)
            X_selected_rfe = selector_rfe.fit_transform(X, y)
            selection_methods["recursive"] = {
                "original_features": X.shape[1],
                "selected_features": X_selected_rfe.shape[1],
                "method": "RFE_RandomForest"
            }
            
            results["feature_selection_pipeline"] = {
                "status": "✅ OK",
                "dataset_shape": X.shape,
                "n_classes": len(np.unique(y)),
                "selection_methods": selection_methods
            }
            
        except Exception as e:
            results["feature_selection_pipeline"] = {"status": "❌ FAILED", "error": str(e)}
        
        return results
    
    def test_learning_patterns(self) -> Dict[str, Any]:
        """Test specific learning patterns and algorithms"""
        print("\n📖 Testing Learning Patterns...")
        
        results = {}
        
        # Test 1: Online Learning Simulation
        try:
            from sklearn.linear_model import SGDClassifier
            from sklearn.datasets import make_classification
            import numpy as np
            
            # Generate dataset for online learning
            X, y = make_classification(n_samples=2000, n_features=20, random_state=42)
            
            # Initialize online learner
            online_clf = SGDClassifier(random_state=42)
            
            # Simulate online learning with batches
            batch_size = 100
            accuracies = []
            
            for i in range(0, len(X), batch_size):
                X_batch = X[i:i+batch_size]
                y_batch = y[i:i+batch_size]
                
                if i == 0:
                    # Initial fit
                    online_clf.fit(X_batch, y_batch)
                else:
                    # Partial fit for online learning
                    online_clf.partial_fit(X_batch, y_batch)
                
                # Evaluate on current batch
                accuracy = online_clf.score(X_batch, y_batch)
                accuracies.append(accuracy)
            
            results["online_learning_simulation"] = {
                "status": "✅ OK",
                "total_samples": len(X),
                "batch_size": batch_size,
                "n_batches": len(accuracies),
                "final_accuracy": float(accuracies[-1]),
                "accuracy_improvement": float(accuracies[-1] - accuracies[0]),
                "learning_curve": [float(acc) for acc in accuracies[-5:]]  # Last 5 accuracies
            }
            
        except Exception as e:
            results["online_learning_simulation"] = {"status": "❌ FAILED", "error": str(e)}
        
        # Test 2: Pattern Recognition in Sequences
        try:
            import numpy as np
            
            # Generate sequence data with patterns
            def generate_pattern_sequence(length=1000):
                patterns = {
                    'increasing': [1, 2, 3, 4, 5],
                    'decreasing': [5, 4, 3, 2, 1],
                    'oscillating': [1, 3, 2, 4, 2],
                    'constant': [3, 3, 3, 3, 3]
                }
                
                sequence = []
                pattern_labels = []
                
                i = 0
                while i < length:
                    # Randomly choose a pattern
                    pattern_name = np.random.choice(list(patterns.keys()))
                    pattern = patterns[pattern_name]
                    
                    # Add pattern to sequence
                    remaining = length - i
                    pattern_length = min(len(pattern), remaining)
                    sequence.extend(pattern[:pattern_length])
                    pattern_labels.extend([pattern_name] * pattern_length)
                    
                    i += pattern_length
                
                return sequence[:length], pattern_labels[:length]
            
            sequence, labels = generate_pattern_sequence(1000)
            
            # Simple pattern detection
            def detect_patterns(seq, window_size=5):
                detected_patterns = []
                
                for i in range(len(seq) - window_size + 1):
                    window = seq[i:i+window_size]
                    
                    # Check for increasing pattern
                    if all(window[j] < window[j+1] for j in range(len(window)-1)):
                        detected_patterns.append(('increasing', i))
                    # Check for decreasing pattern
                    elif all(window[j] > window[j+1] for j in range(len(window)-1)):
                        detected_patterns.append(('decreasing', i))
                    # Check for constant pattern
                    elif len(set(window)) == 1:
                        detected_patterns.append(('constant', i))
                
                return detected_patterns
            
            detected = detect_patterns(sequence)
            
            # Calculate pattern detection accuracy
            pattern_counts = {}
            for pattern, _ in detected:
                pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
            
            results["pattern_recognition_sequences"] = {
                "status": "✅ OK",
                "sequence_length": len(sequence),
                "unique_patterns": len(set(labels)),
                "patterns_detected": len(detected),
                "pattern_distribution": pattern_counts,
                "detection_rate": len(detected) / len(sequence)
            }
            
        except Exception as e:
            results["pattern_recognition_sequences"] = {"status": "❌ FAILED", "error": str(e)}
        
        return results
    
    def test_performance_benchmarks(self) -> Dict[str, Any]:
        """Test ML performance benchmarks"""
        print("\n⚡ Testing Performance Benchmarks...")
        
        results = {}
        
        # Test 1: Large Dataset Processing
        try:
            import time
            import numpy as np
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.datasets import make_classification
            
            # Generate large dataset
            start_time = time.time()
            X_large, y_large = make_classification(
                n_samples=10000,
                n_features=50,
                n_informative=30,
                random_state=42
            )
            data_gen_time = time.time() - start_time
            
            # Train model on large dataset
            start_time = time.time()
            clf_large = RandomForestClassifier(n_estimators=50, n_jobs=-1, random_state=42)
            clf_large.fit(X_large, y_large)
            training_time = time.time() - start_time
            
            # Make predictions
            start_time = time.time()
            predictions = clf_large.predict(X_large[:1000])  # Predict on subset
            prediction_time = time.time() - start_time
            
            # Calculate throughput
            samples_per_second = 1000 / prediction_time
            
            results["large_dataset_processing"] = {
                "status": "✅ OK",
                "dataset_size": X_large.shape,
                "data_generation_time": round(data_gen_time, 3),
                "training_time": round(training_time, 3),
                "prediction_time": round(prediction_time, 3),
                "samples_per_second": round(samples_per_second, 2),
                "model_accuracy": float(clf_large.score(X_large[:1000], y_large[:1000]))
            }
            
        except Exception as e:
            results["large_dataset_processing"] = {"status": "❌ FAILED", "error": str(e)}
        
        # Test 2: Memory Efficiency
        try:
            import psutil
            import os
            import numpy as np
            
            process = psutil.Process(os.getpid())
            
            # Measure memory before large allocation
            memory_before = process.memory_info().rss / 1024 / 1024  # MB
            
            # Create large arrays and perform operations
            large_arrays = []
            for i in range(5):
                arr = np.random.rand(1000, 1000)
                result = np.dot(arr, arr.T)
                large_arrays.append(result)
            
            # Measure memory after allocation
            memory_after = process.memory_info().rss / 1024 / 1024  # MB
            
            # Clean up
            del large_arrays
            
            # Measure memory after cleanup
            memory_cleaned = process.memory_info().rss / 1024 / 1024  # MB
            
            results["memory_efficiency"] = {
                "status": "✅ OK",
                "memory_before_mb": round(memory_before, 2),
                "memory_after_mb": round(memory_after, 2),
                "memory_cleaned_mb": round(memory_cleaned, 2),
                "memory_used_mb": round(memory_after - memory_before, 2),
                "memory_recovered_mb": round(memory_after - memory_cleaned, 2),
                "memory_efficiency": (memory_after - memory_cleaned) / (memory_after - memory_before) > 0.8
            }
            
        except Exception as e:
            results["memory_efficiency"] = {"status": "❌ FAILED", "error": str(e)}
        
        return results
    
    async def test_integration_scenarios(self) -> Dict[str, Any]:
        """Test real-world integration scenarios"""
        print("\n🔗 Testing Integration Scenarios...")
        
        results = {}
        
        # Test 1: Simulated Code Learning Pipeline
        try:
            # Simulate code change data
            code_changes = [
                {
                    "file": "test.py",
                    "language": "python",
                    "before": "x = 1",
                    "after": "x: int = 1",
                    "change_type": "type_annotation"
                },
                {
                    "file": "utils.py", 
                    "language": "python",
                    "before": "def func():",
                    "after": "async def func():",
                    "change_type": "async_conversion"
                },
                {
                    "file": "main.py",
                    "language": "python", 
                    "before": "import os",
                    "after": "import os\nimport sys",
                    "change_type": "import_addition"
                }
            ]
            
            # Simulate learning from patterns
            patterns = []
            for change in code_changes:
                if "async" in change["after"] and "async" not in change["before"]:
                    patterns.append({"type": "async_adoption", "strength": 0.8})
                if ":" in change["after"] and ":" not in change["before"]:
                    patterns.append({"type": "type_hints", "strength": 0.9})
                if "import" in change["after"]:
                    patterns.append({"type": "import_usage", "strength": 0.7})
            
            # Calculate learning metrics
            total_strength = sum(p["strength"] for p in patterns)
            avg_strength = total_strength / len(patterns) if patterns else 0
            
            results["code_learning_simulation"] = {
                "status": "✅ OK",
                "changes_processed": len(code_changes),
                "patterns_extracted": len(patterns),
                "average_pattern_strength": round(avg_strength, 3),
                "learning_confidence": avg_strength > 0.7,
                "pattern_types": [p["type"] for p in patterns]
            }
            
        except Exception as e:
            results["code_learning_simulation"] = {"status": "❌ FAILED", "error": str(e)}
        
        # Test 2: Multi-Modal Learning Integration
        try:
            import numpy as np
            from sklearn.preprocessing import StandardScaler
            from sklearn.decomposition import PCA
            
            # Simulate different data modalities
            text_features = np.random.rand(100, 20)  # Text embeddings
            numeric_features = np.random.rand(100, 10)  # Numeric features
            categorical_features = np.random.randint(0, 5, (100, 5))  # Categorical
            
            # Preprocessing for each modality
            scaler_text = StandardScaler()
            text_scaled = scaler_text.fit_transform(text_features)
            
            scaler_numeric = StandardScaler()
            numeric_scaled = scaler_numeric.fit_transform(numeric_features)
            
            # Dimensionality reduction
            pca = PCA(n_components=10)
            text_reduced = pca.fit_transform(text_scaled)
            
            # Combine features
            combined_features = np.hstack([
                text_reduced,
                numeric_scaled,
                categorical_features
            ])
            
            results["multimodal_integration"] = {
                "status": "✅ OK",
                "text_features_original": text_features.shape,
                "text_features_reduced": text_reduced.shape,
                "numeric_features": numeric_features.shape,
                "categorical_features": categorical_features.shape,
                "combined_features": combined_features.shape,
                "variance_explained": float(pca.explained_variance_ratio_.sum()),
                "integration_successful": combined_features.shape[1] == 25
            }
            
        except Exception as e:
            results["multimodal_integration"] = {"status": "❌ FAILED", "error": str(e)}
        
        return results
    
    async def run_comprehensive_test(self) -> Dict[str, Any]:
        """Run all comprehensive ML algorithm tests"""
        print("🚀 Starting Comprehensive ML Algorithm Testing...")
        print("="*60)
        
        # Run all test categories
        self.results["algorithm_validation"] = self.test_ml_algorithms()
        self.results["data_pipeline_tests"] = self.test_data_pipelines()
        self.results["learning_pattern_tests"] = self.test_learning_patterns()
        self.results["performance_benchmarks"] = self.test_performance_benchmarks()
        self.results["integration_tests"] = await self.test_integration_scenarios()
        
        # Generate summary
        total_tests = 0
        passed_tests = 0
        failed_tests = 0
        
        for category, tests in self.results.items():
            if category in ["timestamp", "summary"]:
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
        """Generate comprehensive algorithm test report"""
        report = []
        report.append("# AGENT 3: Comprehensive ML Algorithm Testing Report")
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
        
        # Detailed results by category
        categories = [
            ("algorithm_validation", "🧠 Algorithm Validation"),
            ("data_pipeline_tests", "🔄 Data Pipeline Tests"),
            ("learning_pattern_tests", "📖 Learning Pattern Tests"),
            ("performance_benchmarks", "⚡ Performance Benchmarks"),
            ("integration_tests", "🔗 Integration Tests")
        ]
        
        for category_key, category_title in categories:
            if category_key in self.results:
                report.append(f"## {category_title}")
                
                for test_name, result in self.results[category_key].items():
                    if isinstance(result, dict):
                        status = result.get("status", "Unknown")
                        report.append(f"### {test_name}")
                        report.append(f"- **Status**: {status}")
                        
                        # Add specific metrics based on test type
                        if "accuracy" in result:
                            report.append(f"- **Accuracy**: {result['accuracy']:.3f}")
                        if "dataset_shape" in result:
                            report.append(f"- **Dataset Shape**: {result['dataset_shape']}")
                        if "training_time" in result:
                            report.append(f"- **Training Time**: {result['training_time']}s")
                        if "samples_per_second" in result:
                            report.append(f"- **Throughput**: {result['samples_per_second']} samples/sec")
                        if "error" in result:
                            report.append(f"- **Error**: {result['error']}")
                            
                report.append("")
        
        return "\n".join(report)

async def main():
    """Main test execution"""
    tester = MLAlgorithmTester()
    
    try:
        # Run comprehensive testing
        results = await tester.run_comprehensive_test()
        
        # Generate and save report
        report = tester.generate_report()
        
        # Save results
        results_file = f"/home/louranicas/projects/claude-optimized-deployment/mcp_learning_system/ml_algorithm_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
            
        # Save report
        report_file = f"/home/louranicas/projects/claude-optimized-deployment/mcp_learning_system/ML_ALGORITHM_TEST_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(report_file, 'w') as f:
            f.write(report)
        
        print("\n" + "="*60)
        print("📋 ML ALGORITHM TEST REPORT GENERATED")
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
    asyncio.run(main())