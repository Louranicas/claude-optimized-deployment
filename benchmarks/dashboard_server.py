#!/usr/bin/env python3
"""
Real-time Performance Dashboard Server
Provides web-based dashboard for monitoring benchmark results and performance trends
"""

import json
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import pandas as pd
import plotly.graph_objs as go
import plotly.utils
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import numpy as np

# Import automation controller for data access
import sys
import os
sys.path.append(os.path.dirname(__file__))
from automation_controller import PerformanceDatabase, TrendAnalyzer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'performance_dashboard_2024'
socketio = SocketIO(app, cors_allowed_origins="*")

class DashboardDataProvider:
    """Provides data for the performance dashboard"""
    
    def __init__(self):
        self.db = PerformanceDatabase()
        self.trend_analyzer = TrendAnalyzer(self.db)
        self.cache = {}
        self.cache_expiry = {}
        self.cache_duration = 300  # 5 minutes
    
    def _is_cache_valid(self, key: str) -> bool:
        """Check if cached data is still valid"""
        return (key in self.cache and 
                key in self.cache_expiry and 
                datetime.now() < self.cache_expiry[key])
    
    def _cache_data(self, key: str, data: Any):
        """Cache data with expiry"""
        self.cache[key] = data
        self.cache_expiry[key] = datetime.now() + timedelta(seconds=self.cache_duration)
    
    def get_dashboard_overview(self) -> Dict[str, Any]:
        """Get dashboard overview data"""
        cache_key = 'dashboard_overview'
        
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]
        
        with sqlite3.connect(self.db.db_path) as conn:
            cursor = conn.cursor()
            
            # Get total benchmark runs in last 24 hours
            cursor.execute('''
                SELECT COUNT(*) FROM benchmark_results 
                WHERE timestamp > datetime('now', '-24 hours')
            ''')
            runs_24h = cursor.fetchone()[0]
            
            # Get total benchmark runs in last 7 days
            cursor.execute('''
                SELECT COUNT(*) FROM benchmark_results 
                WHERE timestamp > datetime('now', '-7 days')
            ''')
            runs_7d = cursor.fetchone()[0]
            
            # Get active alerts count
            cursor.execute('''
                SELECT COUNT(*) FROM regression_alerts 
                WHERE timestamp > datetime('now', '-24 hours')
                AND acknowledged = FALSE
            ''')
            active_alerts = cursor.fetchone()[0]
            
            # Get unique test types
            cursor.execute('''
                SELECT COUNT(DISTINCT test_name) FROM benchmark_results 
                WHERE timestamp > datetime('now', '-7 days')
            ''')
            test_types = cursor.fetchone()[0]
            
            # Get average performance metrics
            cursor.execute('''
                SELECT 
                    AVG(throughput) as avg_throughput,
                    AVG(latency_avg) as avg_latency,
                    AVG(cpu_usage_avg) as avg_cpu,
                    AVG(memory_peak_mb) as avg_memory
                FROM benchmark_results 
                WHERE timestamp > datetime('now', '-24 hours')
                AND throughput IS NOT NULL
            ''')
            avg_metrics = cursor.fetchone()
        
        overview = {
            'runs_24h': runs_24h,
            'runs_7d': runs_7d,
            'active_alerts': active_alerts,
            'test_types': test_types,
            'avg_throughput': avg_metrics[0] if avg_metrics[0] else 0,
            'avg_latency': avg_metrics[1] if avg_metrics[1] else 0,
            'avg_cpu': avg_metrics[2] if avg_metrics[2] else 0,
            'avg_memory': avg_metrics[3] if avg_metrics[3] else 0,
            'last_updated': datetime.now().isoformat()
        }
        
        self._cache_data(cache_key, overview)
        return overview
    
    def get_recent_test_results(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recent test results"""
        cache_key = f'recent_results_{hours}h'
        
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]
        
        with sqlite3.connect(self.db.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT test_name, timestamp, duration, throughput, latency_avg, 
                       cpu_usage_avg, memory_peak_mb, error_rate
                FROM benchmark_results 
                WHERE timestamp > datetime('now', '-{} hours')
                ORDER BY timestamp DESC
                LIMIT 100
            '''.format(hours))
            
            columns = ['test_name', 'timestamp', 'duration', 'throughput', 
                      'latency_avg', 'cpu_usage_avg', 'memory_peak_mb', 'error_rate']
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        self._cache_data(cache_key, results)
        return results
    
    def get_performance_trends(self, test_name: str, days: int = 7) -> Dict[str, Any]:
        """Get performance trends for a specific test"""
        cache_key = f'trends_{test_name}_{days}d'
        
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]
        
        trends = self.trend_analyzer.analyze_trends(test_name, days)
        
        self._cache_data(cache_key, trends)
        return trends
    
    def get_performance_charts_data(self, test_name: str = None, days: int = 7) -> Dict[str, Any]:
        """Get data for performance charts"""
        cache_key = f'charts_{test_name}_{days}d'
        
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]
        
        with sqlite3.connect(self.db.db_path) as conn:
            query = '''
                SELECT test_name, timestamp, throughput, latency_avg, 
                       cpu_usage_avg, memory_peak_mb
                FROM benchmark_results 
                WHERE timestamp > datetime('now', '-{} days')
            '''.format(days)
            
            if test_name:
                query += f" AND test_name = '{test_name}'"
            
            query += " ORDER BY timestamp"
            
            df = pd.read_sql_query(query, conn)
        
        if df.empty:
            return {'error': 'No data available'}
        
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Create charts data
        charts_data = {}
        
        if test_name:
            # Single test detailed view
            charts_data = self._create_single_test_charts(df)
        else:
            # Multi-test overview
            charts_data = self._create_overview_charts(df)
        
        self._cache_data(cache_key, charts_data)
        return charts_data
    
    def _create_single_test_charts(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Create charts for a single test"""
        charts = {}
        
        # Throughput over time
        if 'throughput' in df.columns and not df['throughput'].isna().all():
            charts['throughput'] = {
                'x': df['timestamp'].dt.strftime('%Y-%m-%d %H:%M').tolist(),
                'y': df['throughput'].fillna(0).tolist(),
                'type': 'line',
                'name': 'Throughput (ops/s)',
                'line': {'color': '#1f77b4'}
            }
        
        # Latency over time
        if 'latency_avg' in df.columns and not df['latency_avg'].isna().all():
            charts['latency'] = {
                'x': df['timestamp'].dt.strftime('%Y-%m-%d %H:%M').tolist(),
                'y': df['latency_avg'].fillna(0).tolist(),
                'type': 'line',
                'name': 'Latency (s)',
                'line': {'color': '#ff7f0e'}
            }
        
        # CPU usage over time
        if 'cpu_usage_avg' in df.columns and not df['cpu_usage_avg'].isna().all():
            charts['cpu'] = {
                'x': df['timestamp'].dt.strftime('%Y-%m-%d %H:%M').tolist(),
                'y': df['cpu_usage_avg'].fillna(0).tolist(),
                'type': 'line',
                'name': 'CPU Usage (%)',
                'line': {'color': '#2ca02c'}
            }
        
        # Memory usage over time
        if 'memory_peak_mb' in df.columns and not df['memory_peak_mb'].isna().all():
            charts['memory'] = {
                'x': df['timestamp'].dt.strftime('%Y-%m-%d %H:%M').tolist(),
                'y': df['memory_peak_mb'].fillna(0).tolist(),
                'type': 'line',
                'name': 'Memory (MB)',
                'line': {'color': '#d62728'}
            }
        
        return charts
    
    def _create_overview_charts(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Create overview charts for all tests"""
        charts = {}
        
        # Test performance comparison (latest results)
        latest_by_test = df.groupby('test_name').last().reset_index()
        
        if not latest_by_test.empty:
            charts['test_comparison'] = {
                'x': latest_by_test['test_name'].tolist(),
                'y': latest_by_test['throughput'].fillna(0).tolist(),
                'type': 'bar',
                'name': 'Latest Throughput by Test',
                'marker': {'color': '#1f77b4'}
            }
        
        # Performance trend over time (aggregated)
        daily_avg = df.groupby(df['timestamp'].dt.date).agg({
            'throughput': 'mean',
            'latency_avg': 'mean',
            'cpu_usage_avg': 'mean',
            'memory_peak_mb': 'mean'
        }).reset_index()
        
        if not daily_avg.empty:
            charts['daily_trends'] = {
                'throughput': {
                    'x': daily_avg['timestamp'].astype(str).tolist(),
                    'y': daily_avg['throughput'].fillna(0).tolist(),
                    'type': 'line',
                    'name': 'Avg Throughput',
                    'line': {'color': '#1f77b4'}
                },
                'latency': {
                    'x': daily_avg['timestamp'].astype(str).tolist(),
                    'y': daily_avg['latency_avg'].fillna(0).tolist(),
                    'type': 'line',
                    'name': 'Avg Latency',
                    'line': {'color': '#ff7f0e'},
                    'yaxis': 'y2'
                }
            }
        
        return charts
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get active performance alerts"""
        cache_key = 'active_alerts'
        
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]
        
        with sqlite3.connect(self.db.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT test_name, metric_type, current_value, baseline_value,
                       degradation_percent, severity, timestamp, details
                FROM regression_alerts 
                WHERE timestamp > datetime('now', '-24 hours')
                AND acknowledged = FALSE
                ORDER BY degradation_percent DESC
                LIMIT 20
            ''')
            
            columns = ['test_name', 'metric_type', 'current_value', 'baseline_value',
                      'degradation_percent', 'severity', 'timestamp', 'details']
            alerts = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        self._cache_data(cache_key, alerts)
        return alerts
    
    def get_test_names(self) -> List[str]:
        """Get list of available test names"""
        with sqlite3.connect(self.db.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT DISTINCT test_name FROM benchmark_results 
                WHERE timestamp > datetime('now', '-30 days')
                ORDER BY test_name
            ''')
            
            return [row[0] for row in cursor.fetchall()]

# Global data provider instance
data_provider = DashboardDataProvider()

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/overview')
def api_overview():
    """API endpoint for dashboard overview"""
    return jsonify(data_provider.get_dashboard_overview())

@app.route('/api/recent-results')
def api_recent_results():
    """API endpoint for recent test results"""
    hours = request.args.get('hours', 24, type=int)
    return jsonify(data_provider.get_recent_test_results(hours))

@app.route('/api/performance-charts')
def api_performance_charts():
    """API endpoint for performance charts data"""
    test_name = request.args.get('test_name')
    days = request.args.get('days', 7, type=int)
    return jsonify(data_provider.get_performance_charts_data(test_name, days))

@app.route('/api/trends/<test_name>')
def api_trends(test_name):
    """API endpoint for performance trends"""
    days = request.args.get('days', 7, type=int)
    return jsonify(data_provider.get_performance_trends(test_name, days))

@app.route('/api/alerts')
def api_alerts():
    """API endpoint for active alerts"""
    return jsonify(data_provider.get_active_alerts())

@app.route('/api/test-names')
def api_test_names():
    """API endpoint for available test names"""
    return jsonify(data_provider.get_test_names())

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print('Client connected to dashboard')
    emit('status', {'msg': 'Connected to performance dashboard'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected from dashboard')

def background_thread():
    """Background thread to push real-time updates"""
    while True:
        try:
            # Clear cache to force fresh data
            data_provider.cache.clear()
            data_provider.cache_expiry.clear()
            
            # Get fresh overview data
            overview = data_provider.get_dashboard_overview()
            socketio.emit('overview_update', overview)
            
            # Get fresh alerts
            alerts = data_provider.get_active_alerts()
            socketio.emit('alerts_update', alerts)
            
            time.sleep(30)  # Update every 30 seconds
            
        except Exception as e:
            print(f"Background thread error: {e}")
            time.sleep(60)  # Wait longer on error

# Create dashboard template
dashboard_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Performance Dashboard - CODE Project</title>
    <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 10px;
            padding: 20px;
            margin: 10px 0;
        }
        .alert-card {
            border-left: 5px solid #dc3545;
            margin: 10px 0;
        }
        .chart-container {
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        .status-green { background-color: #28a745; }
        .status-yellow { background-color: #ffc107; }
        .status-red { background-color: #dc3545; }
        
        body {
            background-color: #f8f9fa;
        }
        
        .navbar {
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%) !important;
        }
        
        .refresh-indicator {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1">🚀 CODE Performance Dashboard</span>
            <span class="navbar-text" id="lastUpdate">
                Last updated: Loading...
            </span>
        </div>
    </nav>

    <div class="container-fluid mt-4">
        <!-- Overview Cards -->
        <div class="row">
            <div class="col-md-3">
                <div class="metric-card">
                    <h5>Runs (24h)</h5>
                    <h2 id="runs24h">-</h2>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-card">
                    <h5>Active Alerts</h5>
                    <h2 id="activeAlerts">-</h2>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-card">
                    <h5>Avg Throughput</h5>
                    <h2 id="avgThroughput">-</h2>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-card">
                    <h5>Avg Latency</h5>
                    <h2 id="avgLatency">-</h2>
                </div>
            </div>
        </div>

        <!-- Charts Row -->
        <div class="row">
            <div class="col-md-6">
                <div class="chart-container">
                    <h5>Performance Overview</h5>
                    <div id="overviewChart"></div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="chart-container">
                    <h5>Test Comparison</h5>
                    <div id="comparisonChart"></div>
                </div>
            </div>
        </div>

        <!-- Alerts and Recent Results -->
        <div class="row">
            <div class="col-md-6">
                <div class="chart-container">
                    <h5>🚨 Active Alerts</h5>
                    <div id="alertsList">Loading alerts...</div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="chart-container">
                    <h5>📊 Recent Test Results</h5>
                    <div id="recentResults">Loading results...</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Refresh Indicator -->
    <div class="refresh-indicator">
        <div class="spinner-border text-primary d-none" role="status" id="refreshSpinner">
            <span class="visually-hidden">Loading...</span>
        </div>
    </div>

    <script>
        // Socket.IO connection
        const socket = io();
        
        socket.on('connect', function() {
            console.log('Connected to dashboard');
        });
        
        socket.on('overview_update', function(data) {
            updateOverview(data);
        });
        
        socket.on('alerts_update', function(data) {
            updateAlerts(data);
        });
        
        // Update overview metrics
        function updateOverview(data) {
            document.getElementById('runs24h').textContent = data.runs_24h || '0';
            document.getElementById('activeAlerts').textContent = data.active_alerts || '0';
            document.getElementById('avgThroughput').textContent = 
                data.avg_throughput ? data.avg_throughput.toFixed(1) + ' ops/s' : 'N/A';
            document.getElementById('avgLatency').textContent = 
                data.avg_latency ? data.avg_latency.toFixed(3) + 's' : 'N/A';
            document.getElementById('lastUpdate').textContent = 
                'Last updated: ' + new Date(data.last_updated).toLocaleTimeString();
        }
        
        // Update alerts list
        function updateAlerts(alerts) {
            const alertsContainer = document.getElementById('alertsList');
            
            if (!alerts || alerts.length === 0) {
                alertsContainer.innerHTML = '<div class="text-success">✅ No active alerts</div>';
                return;
            }
            
            let html = '';
            alerts.forEach(alert => {
                const severityClass = alert.severity === 'critical' ? 'danger' : 
                                    alert.severity === 'high' ? 'warning' : 'info';
                html += `
                    <div class="alert alert-${severityClass} alert-card">
                        <strong>${alert.test_name}</strong>: ${alert.metric_type} degraded by 
                        ${alert.degradation_percent.toFixed(1)}% (${alert.severity})
                        <br><small>${new Date(alert.timestamp).toLocaleString()}</small>
                    </div>
                `;
            });
            
            alertsContainer.innerHTML = html;
        }
        
        // Load performance charts
        async function loadCharts() {
            try {
                const response = await axios.get('/api/performance-charts');
                const chartsData = response.data;
                
                if (chartsData.error) {
                    console.log('No chart data available');
                    return;
                }
                
                // Create overview chart
                if (chartsData.daily_trends) {
                    const layout = {
                        title: 'Daily Performance Trends',
                        xaxis: { title: 'Date' },
                        yaxis: { title: 'Throughput (ops/s)', side: 'left' },
                        yaxis2: { title: 'Latency (s)', side: 'right', overlaying: 'y' }
                    };
                    
                    const traces = [chartsData.daily_trends.throughput];
                    if (chartsData.daily_trends.latency) {
                        traces.push(chartsData.daily_trends.latency);
                    }
                    
                    Plotly.newPlot('overviewChart', traces, layout);
                }
                
                // Create test comparison chart
                if (chartsData.test_comparison) {
                    const layout = {
                        title: 'Latest Performance by Test',
                        xaxis: { title: 'Test Name' },
                        yaxis: { title: 'Throughput (ops/s)' }
                    };
                    
                    Plotly.newPlot('comparisonChart', [chartsData.test_comparison], layout);
                }
                
            } catch (error) {
                console.error('Error loading charts:', error);
            }
        }
        
        // Load recent results
        async function loadRecentResults() {
            try {
                const response = await axios.get('/api/recent-results?hours=24');
                const results = response.data;
                
                const container = document.getElementById('recentResults');
                
                if (!results || results.length === 0) {
                    container.innerHTML = '<div class="text-muted">No recent results</div>';
                    return;
                }
                
                let html = '<div class="table-responsive"><table class="table table-sm">';
                html += '<thead><tr><th>Test</th><th>Duration</th><th>Throughput</th><th>Status</th></tr></thead><tbody>';
                
                results.slice(0, 10).forEach(result => {
                    const status = result.error_rate && result.error_rate > 0 ? 'danger' : 'success';
                    const statusIcon = status === 'success' ? '✅' : '❌';
                    const throughput = result.throughput ? result.throughput.toFixed(1) + ' ops/s' : 'N/A';
                    const duration = result.duration ? result.duration.toFixed(3) + 's' : 'N/A';
                    
                    html += `
                        <tr>
                            <td><small>${result.test_name}</small></td>
                            <td><small>${duration}</small></td>
                            <td><small>${throughput}</small></td>
                            <td>${statusIcon}</td>
                        </tr>
                    `;
                });
                
                html += '</tbody></table></div>';
                container.innerHTML = html;
                
            } catch (error) {
                console.error('Error loading recent results:', error);
            }
        }
        
        // Initial load
        async function initDashboard() {
            // Load initial data
            try {
                const overviewResponse = await axios.get('/api/overview');
                updateOverview(overviewResponse.data);
                
                const alertsResponse = await axios.get('/api/alerts');
                updateAlerts(alertsResponse.data);
                
                await loadCharts();
                await loadRecentResults();
                
            } catch (error) {
                console.error('Error initializing dashboard:', error);
            }
        }
        
        // Initialize dashboard on page load
        document.addEventListener('DOMContentLoaded', initDashboard);
        
        // Refresh data periodically
        setInterval(async () => {
            document.getElementById('refreshSpinner').classList.remove('d-none');
            await loadCharts();
            await loadRecentResults();
            document.getElementById('refreshSpinner').classList.add('d-none');
        }, 60000); // Refresh every minute
    </script>
</body>
</html>
'''

# Create templates directory and save template
def setup_templates():
    """Setup Flask templates"""
    templates_dir = Path("/home/louranicas/projects/claude-optimized-deployment/benchmarks/templates")
    templates_dir.mkdir(exist_ok=True)
    
    with open(templates_dir / "dashboard.html", "w") as f:
        f.write(dashboard_template)

def run_dashboard_server(host='localhost', port=5000, debug=False):
    """Run the dashboard server"""
    print(f"🌐 Starting Performance Dashboard Server")
    print(f"📊 Dashboard URL: http://{host}:{port}")
    print("=" * 50)
    
    # Setup templates
    setup_templates()
    
    # Start background thread for real-time updates
    thread = threading.Thread(target=background_thread)
    thread.daemon = True
    thread.start()
    
    # Run the Flask app
    socketio.run(app, host=host, port=port, debug=debug)

if __name__ == "__main__":
    run_dashboard_server(host='0.0.0.0', port=5000, debug=True)