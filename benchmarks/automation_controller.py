#!/usr/bin/env python3
"""
Benchmark Automation Controller
Handles automated execution, scheduling, baseline establishment, and regression detection
"""

import asyncio
import json
import os
import time
import statistics
import schedule
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass, asdict
import numpy as np
import pandas as pd
import sqlite3
import logging
from concurrent.futures import ThreadPoolExecutor
import smtplib
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/louranicas/projects/claude-optimized-deployment/benchmarks/automation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class BenchmarkBaseline:
    """Performance baseline for comparison"""
    test_name: str
    baseline_throughput: Optional[float]
    baseline_latency: Optional[float]
    baseline_cpu_usage: Optional[float]
    baseline_memory_usage: Optional[float]
    established_date: datetime
    sample_count: int
    confidence_interval: float

@dataclass
class RegressionAlert:
    """Performance regression alert"""
    test_name: str
    metric_type: str  # throughput, latency, cpu, memory
    current_value: float
    baseline_value: float
    degradation_percent: float
    severity: str  # low, medium, high, critical
    timestamp: datetime
    details: Dict[str, Any]

class PerformanceDatabase:
    """SQLite database for storing benchmark results and baselines"""
    
    def __init__(self, db_path: str = "/home/louranicas/projects/claude-optimized-deployment/benchmarks/performance.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Benchmark results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS benchmark_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    test_name TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    duration REAL,
                    throughput REAL,
                    latency_avg REAL,
                    latency_p95 REAL,
                    latency_p99 REAL,
                    memory_peak_mb REAL,
                    cpu_usage_avg REAL,
                    error_rate REAL,
                    metadata TEXT,
                    git_commit TEXT,
                    system_config TEXT
                )
            ''')
            
            # Baselines table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    test_name TEXT UNIQUE NOT NULL,
                    baseline_throughput REAL,
                    baseline_latency REAL,
                    baseline_cpu_usage REAL,
                    baseline_memory_usage REAL,
                    established_date TEXT NOT NULL,
                    sample_count INTEGER,
                    confidence_interval REAL
                )
            ''')
            
            # Regression alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS regression_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    test_name TEXT NOT NULL,
                    metric_type TEXT NOT NULL,
                    current_value REAL,
                    baseline_value REAL,
                    degradation_percent REAL,
                    severity TEXT,
                    timestamp TEXT NOT NULL,
                    acknowledged BOOLEAN DEFAULT FALSE,
                    details TEXT
                )
            ''')
            
            conn.commit()
    
    def store_benchmark_result(self, result: Dict[str, Any], git_commit: str = None):
        """Store benchmark result in database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Get system configuration
            system_config = json.dumps({
                'cpu_count': os.cpu_count(),
                'platform': os.uname().sysname,
                'python_version': os.sys.version
            })
            
            cursor.execute('''
                INSERT INTO benchmark_results 
                (test_name, timestamp, duration, throughput, latency_avg, latency_p95, 
                 latency_p99, memory_peak_mb, cpu_usage_avg, error_rate, metadata, 
                 git_commit, system_config)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                result.get('test_name'),
                result.get('timestamp'),
                result.get('duration'),
                result.get('throughput'),
                result.get('latency_avg'),
                result.get('latency_p95'),
                result.get('latency_p99'),
                result.get('memory_peak_mb'),
                result.get('cpu_usage_avg'),
                result.get('error_rate'),
                json.dumps(result.get('metadata', {})),
                git_commit,
                system_config
            ))
            
            conn.commit()
    
    def get_recent_results(self, test_name: str, days: int = 30) -> List[Dict[str, Any]]:
        """Get recent results for a test"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            cursor.execute('''
                SELECT * FROM benchmark_results 
                WHERE test_name = ? AND timestamp > ?
                ORDER BY timestamp DESC
            ''', (test_name, cutoff_date))
            
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def store_baseline(self, baseline: BenchmarkBaseline):
        """Store or update baseline"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO baselines 
                (test_name, baseline_throughput, baseline_latency, baseline_cpu_usage,
                 baseline_memory_usage, established_date, sample_count, confidence_interval)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                baseline.test_name,
                baseline.baseline_throughput,
                baseline.baseline_latency,
                baseline.baseline_cpu_usage,
                baseline.baseline_memory_usage,
                baseline.established_date.isoformat(),
                baseline.sample_count,
                baseline.confidence_interval
            ))
            
            conn.commit()
    
    def get_baseline(self, test_name: str) -> Optional[BenchmarkBaseline]:
        """Get baseline for a test"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM baselines WHERE test_name = ?', (test_name,))
            row = cursor.fetchone()
            
            if row:
                return BenchmarkBaseline(
                    test_name=row[1],
                    baseline_throughput=row[2],
                    baseline_latency=row[3],
                    baseline_cpu_usage=row[4],
                    baseline_memory_usage=row[5],
                    established_date=datetime.fromisoformat(row[6]),
                    sample_count=row[7],
                    confidence_interval=row[8]
                )
            return None
    
    def store_regression_alert(self, alert: RegressionAlert):
        """Store regression alert"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO regression_alerts 
                (test_name, metric_type, current_value, baseline_value, degradation_percent,
                 severity, timestamp, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert.test_name,
                alert.metric_type,
                alert.current_value,
                alert.baseline_value,
                alert.degradation_percent,
                alert.severity,
                alert.timestamp.isoformat(),
                json.dumps(alert.details)
            ))
            
            conn.commit()

class BaselineManager:
    """Manages performance baselines"""
    
    def __init__(self, db: PerformanceDatabase):
        self.db = db
    
    def establish_baseline(self, test_name: str, min_samples: int = 10) -> Optional[BenchmarkBaseline]:
        """Establish baseline from recent stable results"""
        logger.info(f"Establishing baseline for {test_name}")
        
        # Get recent results (last 30 days)
        recent_results = self.db.get_recent_results(test_name, days=30)
        
        if len(recent_results) < min_samples:
            logger.warning(f"Insufficient samples for {test_name}: {len(recent_results)}")
            return None
        
        # Extract metrics
        throughputs = [r['throughput'] for r in recent_results if r['throughput']]
        latencies = [r['latency_avg'] for r in recent_results if r['latency_avg']]
        cpu_usages = [r['cpu_usage_avg'] for r in recent_results if r['cpu_usage_avg']]
        memory_usages = [r['memory_peak_mb'] for r in recent_results if r['memory_peak_mb']]
        
        # Calculate baseline values (median for stability)
        baseline_throughput = statistics.median(throughputs) if throughputs else None
        baseline_latency = statistics.median(latencies) if latencies else None
        baseline_cpu_usage = statistics.median(cpu_usages) if cpu_usages else None
        baseline_memory_usage = statistics.median(memory_usages) if memory_usages else None
        
        # Calculate confidence interval (using standard deviation)
        confidence_interval = 0.95
        if throughputs:
            std_dev = statistics.stdev(throughputs)
            confidence_interval = min(0.99, max(0.90, 1 - (std_dev / baseline_throughput)))
        
        baseline = BenchmarkBaseline(
            test_name=test_name,
            baseline_throughput=baseline_throughput,
            baseline_latency=baseline_latency,
            baseline_cpu_usage=baseline_cpu_usage,
            baseline_memory_usage=baseline_memory_usage,
            established_date=datetime.now(),
            sample_count=len(recent_results),
            confidence_interval=confidence_interval
        )
        
        # Store baseline
        self.db.store_baseline(baseline)
        logger.info(f"Baseline established for {test_name}")
        
        return baseline
    
    def update_baseline_if_needed(self, test_name: str) -> bool:
        """Update baseline if it's outdated or insufficient"""
        baseline = self.db.get_baseline(test_name)
        
        if not baseline:
            self.establish_baseline(test_name)
            return True
        
        # Check if baseline is too old (30 days)
        if (datetime.now() - baseline.established_date).days > 30:
            logger.info(f"Updating outdated baseline for {test_name}")
            self.establish_baseline(test_name)
            return True
        
        # Check if confidence is too low
        if baseline.confidence_interval < 0.90:
            logger.info(f"Updating low-confidence baseline for {test_name}")
            self.establish_baseline(test_name)
            return True
        
        return False

class RegressionDetector:
    """Detects performance regressions"""
    
    def __init__(self, db: PerformanceDatabase):
        self.db = db
        self.thresholds = {
            'throughput_degradation': 10.0,  # 10% degradation
            'latency_increase': 15.0,        # 15% increase
            'cpu_increase': 20.0,            # 20% increase
            'memory_increase': 25.0          # 25% increase
        }
    
    def detect_regression(self, result: Dict[str, Any]) -> List[RegressionAlert]:
        """Detect regressions in benchmark result"""
        test_name = result.get('test_name')
        baseline = self.db.get_baseline(test_name)
        
        if not baseline:
            logger.warning(f"No baseline found for {test_name}")
            return []
        
        alerts = []
        
        # Check throughput regression
        if result.get('throughput') and baseline.baseline_throughput:
            degradation = ((baseline.baseline_throughput - result['throughput']) / 
                          baseline.baseline_throughput * 100)
            
            if degradation > self.thresholds['throughput_degradation']:
                severity = self._determine_severity(degradation, self.thresholds['throughput_degradation'])
                alerts.append(RegressionAlert(
                    test_name=test_name,
                    metric_type='throughput',
                    current_value=result['throughput'],
                    baseline_value=baseline.baseline_throughput,
                    degradation_percent=degradation,
                    severity=severity,
                    timestamp=datetime.now(),
                    details={'threshold': self.thresholds['throughput_degradation']}
                ))
        
        # Check latency regression
        if result.get('latency_avg') and baseline.baseline_latency:
            increase = ((result['latency_avg'] - baseline.baseline_latency) / 
                       baseline.baseline_latency * 100)
            
            if increase > self.thresholds['latency_increase']:
                severity = self._determine_severity(increase, self.thresholds['latency_increase'])
                alerts.append(RegressionAlert(
                    test_name=test_name,
                    metric_type='latency',
                    current_value=result['latency_avg'],
                    baseline_value=baseline.baseline_latency,
                    degradation_percent=increase,
                    severity=severity,
                    timestamp=datetime.now(),
                    details={'threshold': self.thresholds['latency_increase']}
                ))
        
        # Check CPU usage regression
        if result.get('cpu_usage_avg') and baseline.baseline_cpu_usage:
            increase = ((result['cpu_usage_avg'] - baseline.baseline_cpu_usage) / 
                       baseline.baseline_cpu_usage * 100)
            
            if increase > self.thresholds['cpu_increase']:
                severity = self._determine_severity(increase, self.thresholds['cpu_increase'])
                alerts.append(RegressionAlert(
                    test_name=test_name,
                    metric_type='cpu_usage',
                    current_value=result['cpu_usage_avg'],
                    baseline_value=baseline.baseline_cpu_usage,
                    degradation_percent=increase,
                    severity=severity,
                    timestamp=datetime.now(),
                    details={'threshold': self.thresholds['cpu_increase']}
                ))
        
        # Check memory usage regression
        if result.get('memory_peak_mb') and baseline.baseline_memory_usage:
            increase = ((result['memory_peak_mb'] - baseline.baseline_memory_usage) / 
                       baseline.baseline_memory_usage * 100)
            
            if increase > self.thresholds['memory_increase']:
                severity = self._determine_severity(increase, self.thresholds['memory_increase'])
                alerts.append(RegressionAlert(
                    test_name=test_name,
                    metric_type='memory_usage',
                    current_value=result['memory_peak_mb'],
                    baseline_value=baseline.baseline_memory_usage,
                    degradation_percent=increase,
                    severity=severity,
                    timestamp=datetime.now(),
                    details={'threshold': self.thresholds['memory_increase']}
                ))
        
        return alerts
    
    def _determine_severity(self, degradation: float, threshold: float) -> str:
        """Determine alert severity based on degradation"""
        if degradation >= threshold * 3:
            return 'critical'
        elif degradation >= threshold * 2:
            return 'high'
        elif degradation >= threshold * 1.5:
            return 'medium'
        else:
            return 'low'

class TrendAnalyzer:
    """Analyzes performance trends over time"""
    
    def __init__(self, db: PerformanceDatabase):
        self.db = db
    
    def analyze_trends(self, test_name: str, days: int = 30) -> Dict[str, Any]:
        """Analyze performance trends for a test"""
        results = self.db.get_recent_results(test_name, days)
        
        if len(results) < 5:
            return {'error': 'Insufficient data for trend analysis'}
        
        # Convert to DataFrame for easier analysis
        df = pd.DataFrame(results)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        
        trends = {}
        
        # Analyze throughput trend
        if 'throughput' in df.columns and df['throughput'].notna().sum() > 3:
            throughput_trend = self._calculate_trend(df['throughput'].dropna())
            trends['throughput'] = throughput_trend
        
        # Analyze latency trend
        if 'latency_avg' in df.columns and df['latency_avg'].notna().sum() > 3:
            latency_trend = self._calculate_trend(df['latency_avg'].dropna())
            trends['latency'] = latency_trend
        
        # Analyze CPU usage trend
        if 'cpu_usage_avg' in df.columns and df['cpu_usage_avg'].notna().sum() > 3:
            cpu_trend = self._calculate_trend(df['cpu_usage_avg'].dropna())
            trends['cpu_usage'] = cpu_trend
        
        # Analyze memory usage trend
        if 'memory_peak_mb' in df.columns and df['memory_peak_mb'].notna().sum() > 3:
            memory_trend = self._calculate_trend(df['memory_peak_mb'].dropna())
            trends['memory_usage'] = memory_trend
        
        return {
            'test_name': test_name,
            'analysis_period_days': days,
            'sample_count': len(results),
            'trends': trends,
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def _calculate_trend(self, series: pd.Series) -> Dict[str, Any]:
        """Calculate trend statistics for a metric series"""
        values = series.values
        x = np.arange(len(values))
        
        # Linear regression for trend
        slope, intercept = np.polyfit(x, values, 1)
        
        # Calculate trend direction and strength
        trend_direction = 'improving' if slope < 0 else 'degrading' if slope > 0 else 'stable'
        trend_strength = abs(slope) / np.mean(values) * 100  # Percentage change per sample
        
        # Calculate variability
        coefficient_of_variation = np.std(values) / np.mean(values) * 100
        
        return {
            'direction': trend_direction,
            'strength_percent_per_sample': trend_strength,
            'slope': slope,
            'mean': np.mean(values),
            'std_dev': np.std(values),
            'coefficient_of_variation': coefficient_of_variation,
            'min': np.min(values),
            'max': np.max(values),
            'latest_value': values[-1],
            'trend_classification': self._classify_trend(trend_direction, trend_strength, coefficient_of_variation)
        }
    
    def _classify_trend(self, direction: str, strength: float, variability: float) -> str:
        """Classify trend based on direction, strength, and variability"""
        if variability > 20:
            return 'highly_variable'
        elif direction == 'stable':
            return 'stable'
        elif strength < 1:
            return f'slightly_{direction}'
        elif strength < 5:
            return f'moderately_{direction}'
        else:
            return f'strongly_{direction}'

class AutomationController:
    """Main automation controller"""
    
    def __init__(self):
        self.db = PerformanceDatabase()
        self.baseline_manager = BaselineManager(self.db)
        self.regression_detector = RegressionDetector(self.db)
        self.trend_analyzer = TrendAnalyzer(self.db)
        self.notification_config = self._load_notification_config()
        
    def _load_notification_config(self) -> Dict[str, Any]:
        """Load notification configuration"""
        config_path = "/home/louranicas/projects/claude-optimized-deployment/benchmarks/notification_config.json"
        
        default_config = {
            'email': {
                'enabled': False,
                'smtp_server': 'localhost',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'recipients': []
            },
            'slack': {
                'enabled': False,
                'webhook_url': ''
            }
        }
        
        try:
            if Path(config_path).exists():
                with open(config_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load notification config: {e}")
        
        return default_config
    
    def run_automated_benchmark(self, benchmark_type: str = 'comprehensive') -> Dict[str, Any]:
        """Run automated benchmark"""
        logger.info(f"Starting automated benchmark: {benchmark_type}")
        
        try:
            # Get current git commit
            git_commit = self._get_git_commit()
            
            # Run benchmark
            if benchmark_type == 'comprehensive':
                result = subprocess.run([
                    'python3', 
                    '/home/louranicas/projects/claude-optimized-deployment/benchmarks/performance_suite.py'
                ], capture_output=True, text=True, timeout=3600)  # 1 hour timeout
            elif benchmark_type == 'quick':
                result = subprocess.run([
                    'python3', 
                    '/home/louranicas/projects/claude-optimized-deployment/benchmarks/quick_benchmark.py'
                ], capture_output=True, text=True, timeout=900)  # 15 minute timeout
            else:
                raise ValueError(f"Unknown benchmark type: {benchmark_type}")
            
            if result.returncode != 0:
                logger.error(f"Benchmark failed: {result.stderr}")
                return {'status': 'failed', 'error': result.stderr}
            
            # Load and process results
            results_file = self._find_latest_results_file()
            if results_file:
                results = self._process_benchmark_results(results_file, git_commit)
                return {'status': 'success', 'results': results}
            else:
                logger.error("No results file found")
                return {'status': 'failed', 'error': 'No results file found'}
                
        except Exception as e:
            logger.error(f"Automated benchmark failed: {e}")
            return {'status': 'failed', 'error': str(e)}
    
    def _get_git_commit(self) -> str:
        """Get current git commit hash"""
        try:
            result = subprocess.run(['git', 'rev-parse', 'HEAD'], 
                                  capture_output=True, text=True, 
                                  cwd='/home/louranicas/projects/claude-optimized-deployment')
            return result.stdout.strip() if result.returncode == 0 else 'unknown'
        except Exception:
            return 'unknown'
    
    def _find_latest_results_file(self) -> Optional[str]:
        """Find the latest benchmark results file"""
        benchmarks_dir = Path("/home/louranicas/projects/claude-optimized-deployment/benchmarks")
        
        # Look for JSON results files
        json_files = list(benchmarks_dir.glob("*benchmark_results_*.json"))
        
        if not json_files:
            return None
        
        # Return the most recent file
        latest_file = max(json_files, key=lambda p: p.stat().st_mtime)
        return str(latest_file)
    
    def _process_benchmark_results(self, results_file: str, git_commit: str) -> Dict[str, Any]:
        """Process benchmark results and detect regressions"""
        with open(results_file, 'r') as f:
            results = json.load(f)
        
        processed_results = []
        regression_alerts = []
        
        for result in results:
            # Store result in database
            self.db.store_benchmark_result(result, git_commit)
            
            # Update baseline if needed
            test_name = result.get('test_name')
            self.baseline_manager.update_baseline_if_needed(test_name)
            
            # Detect regressions
            alerts = self.regression_detector.detect_regression(result)
            regression_alerts.extend(alerts)
            
            # Store alerts
            for alert in alerts:
                self.db.store_regression_alert(alert)
            
            processed_results.append(result)
        
        # Send notifications if there are regressions
        if regression_alerts:
            self._send_regression_notifications(regression_alerts)
        
        return {
            'processed_count': len(processed_results),
            'regression_alerts': len(regression_alerts),
            'git_commit': git_commit
        }
    
    def _send_regression_notifications(self, alerts: List[RegressionAlert]):
        """Send regression notifications"""
        if not alerts:
            return
        
        high_severity_alerts = [a for a in alerts if a.severity in ['high', 'critical']]
        
        if high_severity_alerts and self.notification_config['email']['enabled']:
            self._send_email_notification(high_severity_alerts)
        
        if alerts and self.notification_config['slack']['enabled']:
            self._send_slack_notification(alerts)
    
    def _send_email_notification(self, alerts: List[RegressionAlert]):
        """Send email notification for regressions"""
        try:
            config = self.notification_config['email']
            
            msg = MimeMultipart()
            msg['From'] = config['username']
            msg['To'] = ', '.join(config['recipients'])
            msg['Subject'] = f"Performance Regression Alert - {len(alerts)} issues detected"
            
            body = "Performance regression detected:\n\n"
            for alert in alerts:
                body += f"- {alert.test_name}: {alert.metric_type} degraded by {alert.degradation_percent:.1f}% ({alert.severity})\n"
            
            msg.attach(MimeText(body, 'plain'))
            
            server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
            server.starttls()
            server.login(config['username'], config['password'])
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email notification sent for {len(alerts)} alerts")
            
        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")
    
    def _send_slack_notification(self, alerts: List[RegressionAlert]):
        """Send Slack notification for regressions"""
        try:
            import requests
            
            webhook_url = self.notification_config['slack']['webhook_url']
            
            message = f"🚨 Performance regression detected ({len(alerts)} issues):\n"
            for alert in alerts:
                emoji = "🔴" if alert.severity == 'critical' else "🟠" if alert.severity == 'high' else "🟡"
                message += f"{emoji} {alert.test_name}: {alert.metric_type} degraded by {alert.degradation_percent:.1f}%\n"
            
            payload = {'text': message}
            
            response = requests.post(webhook_url, json=payload)
            response.raise_for_status()
            
            logger.info(f"Slack notification sent for {len(alerts)} alerts")
            
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
    
    def schedule_benchmarks(self):
        """Schedule automated benchmarks"""
        logger.info("Setting up benchmark schedule")
        
        # Schedule comprehensive benchmarks daily at 2 AM
        schedule.every().day.at("02:00").do(
            lambda: self.run_automated_benchmark('comprehensive')
        )
        
        # Schedule quick benchmarks every 6 hours
        schedule.every(6).hours.do(
            lambda: self.run_automated_benchmark('quick')
        )
        
        # Schedule baseline updates weekly
        schedule.every().sunday.at("03:00").do(
            self._update_all_baselines
        )
        
        logger.info("Benchmark schedule configured")
    
    def _update_all_baselines(self):
        """Update all baselines"""
        logger.info("Updating all baselines")
        
        # Get all unique test names from recent results
        with sqlite3.connect(self.db.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT DISTINCT test_name FROM benchmark_results 
                WHERE timestamp > datetime('now', '-30 days')
            ''')
            test_names = [row[0] for row in cursor.fetchall()]
        
        for test_name in test_names:
            try:
                self.baseline_manager.establish_baseline(test_name)
            except Exception as e:
                logger.error(f"Failed to update baseline for {test_name}: {e}")
        
        logger.info(f"Updated baselines for {len(test_names)} tests")
    
    def generate_dashboard_data(self) -> Dict[str, Any]:
        """Generate data for performance dashboard"""
        with sqlite3.connect(self.db.db_path) as conn:
            cursor = conn.cursor()
            
            # Get recent results summary
            cursor.execute('''
                SELECT test_name, COUNT(*) as count, 
                       AVG(throughput) as avg_throughput,
                       AVG(latency_avg) as avg_latency,
                       MAX(timestamp) as latest_run
                FROM benchmark_results 
                WHERE timestamp > datetime('now', '-7 days')
                GROUP BY test_name
            ''')
            
            recent_summary = []
            for row in cursor.fetchall():
                recent_summary.append({
                    'test_name': row[0],
                    'run_count': row[1],
                    'avg_throughput': row[2],
                    'avg_latency': row[3],
                    'latest_run': row[4]
                })
            
            # Get active alerts
            cursor.execute('''
                SELECT test_name, metric_type, severity, degradation_percent, timestamp
                FROM regression_alerts 
                WHERE timestamp > datetime('now', '-24 hours')
                AND acknowledged = FALSE
                ORDER BY degradation_percent DESC
            ''')
            
            active_alerts = []
            for row in cursor.fetchall():
                active_alerts.append({
                    'test_name': row[0],
                    'metric_type': row[1],
                    'severity': row[2],
                    'degradation_percent': row[3],
                    'timestamp': row[4]
                })
        
        return {
            'recent_summary': recent_summary,
            'active_alerts': active_alerts,
            'dashboard_updated': datetime.now().isoformat()
        }
    
    def run_scheduler(self):
        """Run the benchmark scheduler"""
        logger.info("Starting benchmark automation controller")
        
        self.schedule_benchmarks()
        
        while True:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
            except KeyboardInterrupt:
                logger.info("Scheduler stopped by user")
                break
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                time.sleep(300)  # Wait 5 minutes before retrying

if __name__ == "__main__":
    controller = AutomationController()
    
    # Run a test benchmark
    result = controller.run_automated_benchmark('comprehensive')
    print(f"Test result: {result}")
    
    # Generate dashboard data
    dashboard_data = controller.generate_dashboard_data()
    print(f"Dashboard data: {json.dumps(dashboard_data, indent=2)}")