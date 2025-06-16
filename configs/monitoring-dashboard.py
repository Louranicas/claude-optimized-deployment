#!/usr/bin/env python3
"""
Advanced Hardware Monitoring Dashboard for AMD Ryzen 7 7800X3D + RX 7900 XT
Real-time monitoring with web interface and alerts
"""

import asyncio
import json
import time
import subprocess
import psutil
import aiohttp
from aiohttp import web
import aiofiles
import websockets
from datetime import datetime
import sqlite3
import os
import re
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HardwareMonitor:
    def __init__(self):
        self.db_path = Path.home() / ".config" / "hardware_monitor" / "metrics.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_database()
        self.clients = set()
        
    def init_database(self):
        """Initialize SQLite database for metrics storage"""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS metrics (
                timestamp INTEGER PRIMARY KEY,
                cpu_temp REAL,
                cpu_usage REAL,
                cpu_freq REAL,
                gpu_temp REAL,
                gpu_usage REAL,
                gpu_power REAL,
                memory_used REAL,
                memory_total REAL,
                nvme_temp REAL,
                disk_io_read REAL,
                disk_io_write REAL,
                network_sent REAL,
                network_recv REAL
            )
        """)
        conn.commit()
        conn.close()
        
    async def get_cpu_metrics(self):
        """Get CPU metrics including temperature and frequency"""
        try:
            # CPU usage
            cpu_usage = psutil.cpu_percent(interval=0.1)
            
            # CPU frequency
            cpu_freq = psutil.cpu_freq()
            current_freq = cpu_freq.current if cpu_freq else 0
            
            # CPU temperature
            cpu_temp = 0
            try:
                temps = psutil.sensors_temperatures()
                if 'k10temp' in temps:
                    cpu_temp = temps['k10temp'][0].current
                elif 'coretemp' in temps:
                    cpu_temp = max([sensor.current for sensor in temps['coretemp']])
            except:
                pass
                
            return {
                'usage': cpu_usage,
                'frequency': current_freq,
                'temperature': cpu_temp,
                'cores': psutil.cpu_count(),
                'load_avg': os.getloadavg()
            }
        except Exception as e:
            logger.error(f"Error getting CPU metrics: {e}")
            return {}
    
    async def get_gpu_metrics(self):
        """Get GPU metrics using rocm-smi"""
        try:
            result = subprocess.run(['rocm-smi', '--showtemp', '--showpower', '--showuse', '--json'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                gpu_data = data.get('card0', {})
                
                return {
                    'temperature': gpu_data.get('Temperature (Sensor edge) (C)', 0),
                    'power': gpu_data.get('Average Graphics Package Power (W)', 0),
                    'usage': gpu_data.get('GPU use (%)', 0),
                    'memory_used': gpu_data.get('GPU Memory Used (B)', 0) / (1024**3),  # GB
                    'memory_total': 20.0  # RX 7900 XT has 20GB VRAM
                }
            else:
                return {}
        except Exception as e:
            logger.error(f"Error getting GPU metrics: {e}")
            return {}
    
    async def get_memory_metrics(self):
        """Get memory and swap metrics"""
        try:
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            return {
                'total': memory.total / (1024**3),  # GB
                'used': memory.used / (1024**3),    # GB
                'available': memory.available / (1024**3),  # GB
                'percent': memory.percent,
                'swap_total': swap.total / (1024**3),
                'swap_used': swap.used / (1024**3),
                'swap_percent': swap.percent
            }
        except Exception as e:
            logger.error(f"Error getting memory metrics: {e}")
            return {}
    
    async def get_storage_metrics(self):
        """Get storage metrics for NVMe and HDD"""
        try:
            disk_io = psutil.disk_io_counters()
            disk_usage = psutil.disk_usage('/')
            
            # NVMe temperature
            nvme_temp = 0
            try:
                result = subprocess.run(['sudo', 'smartctl', '-A', '/dev/nvme0'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'Temperature' in line:
                            match = re.search(r'(\d+)', line)
                            if match:
                                nvme_temp = int(match.group(1))
                                break
            except:
                pass
            
            return {
                'disk_total': disk_usage.total / (1024**3),  # GB
                'disk_used': disk_usage.used / (1024**3),    # GB
                'disk_free': disk_usage.free / (1024**3),    # GB
                'disk_percent': (disk_usage.used / disk_usage.total) * 100,
                'io_read': disk_io.read_bytes / (1024**2) if disk_io else 0,  # MB
                'io_write': disk_io.write_bytes / (1024**2) if disk_io else 0,  # MB
                'nvme_temp': nvme_temp
            }
        except Exception as e:
            logger.error(f"Error getting storage metrics: {e}")
            return {}
    
    async def get_network_metrics(self):
        """Get network metrics"""
        try:
            net_io = psutil.net_io_counters()
            
            return {
                'bytes_sent': net_io.bytes_sent / (1024**2),  # MB
                'bytes_recv': net_io.bytes_recv / (1024**2),  # MB
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            }
        except Exception as e:
            logger.error(f"Error getting network metrics: {e}")
            return {}
    
    async def get_process_metrics(self):
        """Get top processes by CPU and memory usage"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Sort by CPU usage and get top 10
            cpu_top = sorted(processes, key=lambda x: x.get('cpu_percent', 0), reverse=True)[:10]
            mem_top = sorted(processes, key=lambda x: x.get('memory_percent', 0), reverse=True)[:10]
            
            return {
                'cpu_top': cpu_top,
                'memory_top': mem_top
            }
        except Exception as e:
            logger.error(f"Error getting process metrics: {e}")
            return {}
    
    async def collect_metrics(self):
        """Collect all metrics and store in database"""
        try:
            cpu = await self.get_cpu_metrics()
            gpu = await self.get_gpu_metrics()
            memory = await self.get_memory_metrics()
            storage = await self.get_storage_metrics()
            network = await self.get_network_metrics()
            processes = await self.get_process_metrics()
            
            timestamp = int(time.time())
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                INSERT INTO metrics VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp,
                cpu.get('temperature', 0),
                cpu.get('usage', 0),
                cpu.get('frequency', 0),
                gpu.get('temperature', 0),
                gpu.get('usage', 0),
                gpu.get('power', 0),
                memory.get('used', 0),
                memory.get('total', 0),
                storage.get('nvme_temp', 0),
                storage.get('io_read', 0),
                storage.get('io_write', 0),
                network.get('bytes_sent', 0),
                network.get('bytes_recv', 0)
            ))
            conn.commit()
            conn.close()
            
            # Prepare data for web interface
            data = {
                'timestamp': timestamp,
                'cpu': cpu,
                'gpu': gpu,
                'memory': memory,
                'storage': storage,
                'network': network,
                'processes': processes
            }
            
            return data
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
            return {}
    
    async def websocket_handler(self, websocket, path):
        """Handle WebSocket connections for real-time updates"""
        self.clients.add(websocket)
        try:
            await websocket.wait_closed()
        finally:
            self.clients.remove(websocket)
    
    async def broadcast_metrics(self, data):
        """Broadcast metrics to all connected WebSocket clients"""
        if self.clients:
            message = json.dumps(data)
            await asyncio.gather(
                *[client.send(message) for client in self.clients],
                return_exceptions=True
            )
    
    async def monitoring_loop(self):
        """Main monitoring loop"""
        while True:
            try:
                data = await self.collect_metrics()
                if data:
                    await self.broadcast_metrics(data)
                await asyncio.sleep(2)  # Collect metrics every 2 seconds
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(5)

# Web interface
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>AMD System Monitor</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a1a; color: #fff; }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { background: #2a2a2a; border-radius: 8px; padding: 20px; border: 1px solid #444; }
        .card h3 { margin-top: 0; color: #ff6b35; }
        .metric { display: flex; justify-content: space-between; margin: 10px 0; }
        .metric-value { font-weight: bold; color: #4CAF50; }
        .progress-bar { width: 100%; height: 20px; background: #444; border-radius: 10px; overflow: hidden; margin: 5px 0; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #4CAF50, #ff6b35); transition: width 0.3s; }
        .high-temp { color: #ff4444 !important; }
        .high-usage { color: #ffaa00 !important; }
        .process-list { max-height: 200px; overflow-y: auto; }
        .process { display: flex; justify-content: space-between; padding: 2px 0; font-size: 0.9em; }
        .status-indicator { width: 12px; height: 12px; border-radius: 50%; display: inline-block; margin-right: 5px; }
        .status-good { background: #4CAF50; }
        .status-warning { background: #ffaa00; }
        .status-critical { background: #ff4444; }
        h1 { text-align: center; color: #ff6b35; }
        .timestamp { text-align: center; color: #888; margin-bottom: 20px; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <h1>AMD Ryzen 7 7800X3D + RX 7900 XT System Monitor</h1>
    <div class="timestamp" id="timestamp"></div>
    
    <div class="dashboard">
        <div class="card">
            <h3>🔥 CPU (Ryzen 7 7800X3D)</h3>
            <div class="metric">
                <span>Temperature:</span>
                <span class="metric-value" id="cpu-temp">0°C</span>
            </div>
            <div class="metric">
                <span>Usage:</span>
                <span class="metric-value" id="cpu-usage">0%</span>
            </div>
            <div class="progress-bar">
                <div class="progress-fill" id="cpu-usage-bar"></div>
            </div>
            <div class="metric">
                <span>Frequency:</span>
                <span class="metric-value" id="cpu-freq">0 MHz</span>
            </div>
            <div class="metric">
                <span>Load Average:</span>
                <span class="metric-value" id="cpu-load">0, 0, 0</span>
            </div>
        </div>
        
        <div class="card">
            <h3>🎮 GPU (RX 7900 XT)</h3>
            <div class="metric">
                <span>Temperature:</span>
                <span class="metric-value" id="gpu-temp">0°C</span>
            </div>
            <div class="metric">
                <span>Usage:</span>
                <span class="metric-value" id="gpu-usage">0%</span>
            </div>
            <div class="progress-bar">
                <div class="progress-fill" id="gpu-usage-bar"></div>
            </div>
            <div class="metric">
                <span>Power:</span>
                <span class="metric-value" id="gpu-power">0W</span>
            </div>
            <div class="metric">
                <span>VRAM:</span>
                <span class="metric-value" id="gpu-memory">0/20 GB</span>
            </div>
        </div>
        
        <div class="card">
            <h3>💾 Memory (32GB DDR5)</h3>
            <div class="metric">
                <span>Used:</span>
                <span class="metric-value" id="memory-used">0 GB</span>
            </div>
            <div class="metric">
                <span>Usage:</span>
                <span class="metric-value" id="memory-percent">0%</span>
            </div>
            <div class="progress-bar">
                <div class="progress-fill" id="memory-bar"></div>
            </div>
            <div class="metric">
                <span>Available:</span>
                <span class="metric-value" id="memory-available">0 GB</span>
            </div>
            <div class="metric">
                <span>Swap:</span>
                <span class="metric-value" id="swap-used">0 GB</span>
            </div>
        </div>
        
        <div class="card">
            <h3>💿 Storage</h3>
            <div class="metric">
                <span>NVMe Temp:</span>
                <span class="metric-value" id="nvme-temp">0°C</span>
            </div>
            <div class="metric">
                <span>Disk Usage:</span>
                <span class="metric-value" id="disk-usage">0%</span>
            </div>
            <div class="progress-bar">
                <div class="progress-fill" id="disk-bar"></div>
            </div>
            <div class="metric">
                <span>Free Space:</span>
                <span class="metric-value" id="disk-free">0 GB</span>
            </div>
            <div class="metric">
                <span>I/O Read:</span>
                <span class="metric-value" id="io-read">0 MB</span>
            </div>
            <div class="metric">
                <span>I/O Write:</span>
                <span class="metric-value" id="io-write">0 MB</span>
            </div>
        </div>
        
        <div class="card">
            <h3>🌐 Network</h3>
            <div class="metric">
                <span>Sent:</span>
                <span class="metric-value" id="net-sent">0 MB</span>
            </div>
            <div class="metric">
                <span>Received:</span>
                <span class="metric-value" id="net-recv">0 MB</span>
            </div>
        </div>
        
        <div class="card">
            <h3>⚡ Top Processes (CPU)</h3>
            <div class="process-list" id="cpu-processes"></div>
        </div>
        
        <div class="card">
            <h3>🧠 Top Processes (Memory)</h3>
            <div class="process-list" id="memory-processes"></div>
        </div>
    </div>
    
    <script>
        const ws = new WebSocket('ws://localhost:8765');
        
        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            updateDashboard(data);
        };
        
        function updateDashboard(data) {
            document.getElementById('timestamp').textContent = new Date(data.timestamp * 1000).toLocaleString();
            
            // CPU metrics
            const cpu = data.cpu || {};
            updateElement('cpu-temp', `${cpu.temperature?.toFixed(1) || 0}°C`, cpu.temperature > 80);
            updateElement('cpu-usage', `${cpu.usage?.toFixed(1) || 0}%`, cpu.usage > 80);
            updateElement('cpu-freq', `${cpu.frequency?.toFixed(0) || 0} MHz`);
            updateElement('cpu-load', cpu.load_avg ? cpu.load_avg.map(x => x.toFixed(2)).join(', ') : '0, 0, 0');
            updateProgressBar('cpu-usage-bar', cpu.usage || 0);
            
            // GPU metrics
            const gpu = data.gpu || {};
            updateElement('gpu-temp', `${gpu.temperature?.toFixed(1) || 0}°C`, gpu.temperature > 85);
            updateElement('gpu-usage', `${gpu.usage?.toFixed(1) || 0}%`, gpu.usage > 90);
            updateElement('gpu-power', `${gpu.power?.toFixed(0) || 0}W`);
            updateElement('gpu-memory', `${gpu.memory_used?.toFixed(1) || 0}/${gpu.memory_total || 20} GB`);
            updateProgressBar('gpu-usage-bar', gpu.usage || 0);
            
            // Memory metrics
            const memory = data.memory || {};
            updateElement('memory-used', `${memory.used?.toFixed(1) || 0} GB`);
            updateElement('memory-percent', `${memory.percent?.toFixed(1) || 0}%`, memory.percent > 85);
            updateElement('memory-available', `${memory.available?.toFixed(1) || 0} GB`);
            updateElement('swap-used', `${memory.swap_used?.toFixed(1) || 0} GB`);
            updateProgressBar('memory-bar', memory.percent || 0);
            
            // Storage metrics
            const storage = data.storage || {};
            updateElement('nvme-temp', `${storage.nvme_temp || 0}°C`, storage.nvme_temp > 70);
            updateElement('disk-usage', `${storage.disk_percent?.toFixed(1) || 0}%`);
            updateElement('disk-free', `${storage.disk_free?.toFixed(1) || 0} GB`);
            updateElement('io-read', `${storage.io_read?.toFixed(1) || 0} MB`);
            updateElement('io-write', `${storage.io_write?.toFixed(1) || 0} MB`);
            updateProgressBar('disk-bar', storage.disk_percent || 0);
            
            // Network metrics
            const network = data.network || {};
            updateElement('net-sent', `${network.bytes_sent?.toFixed(1) || 0} MB`);
            updateElement('net-recv', `${network.bytes_recv?.toFixed(1) || 0} MB`);
            
            // Process lists
            updateProcessList('cpu-processes', data.processes?.cpu_top || []);
            updateProcessList('memory-processes', data.processes?.memory_top || []);
        }
        
        function updateElement(id, value, isHigh = false) {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = value;
                element.className = isHigh ? 'metric-value high-temp' : 'metric-value';
            }
        }
        
        function updateProgressBar(id, percentage) {
            const element = document.getElementById(id);
            if (element) {
                element.style.width = `${percentage}%`;
            }
        }
        
        function updateProcessList(id, processes) {
            const element = document.getElementById(id);
            if (element && processes) {
                element.innerHTML = processes.slice(0, 8).map(proc => 
                    `<div class="process">
                        <span>${proc.name || 'unknown'}</span>
                        <span>${(id.includes('cpu') ? proc.cpu_percent : proc.memory_percent)?.toFixed(1) || 0}%</span>
                    </div>`
                ).join('');
            }
        }
        
        // Reconnect on connection loss
        ws.onclose = function() {
            setTimeout(() => location.reload(), 5000);
        };
    </script>
</body>
</html>
"""

async def web_handler(request):
    """Serve the web interface"""
    return web.Response(text=HTML_TEMPLATE, content_type='text/html')

async def main():
    """Main function to start the monitoring system"""
    monitor = HardwareMonitor()
    
    # Start WebSocket server
    websocket_server = websockets.serve(monitor.websocket_handler, "localhost", 8765)
    
    # Start web server
    app = web.Application()
    app.router.add_get('/', web_handler)
    web_runner = web.AppRunner(app)
    await web_runner.setup()
    site = web.TCPSite(web_runner, 'localhost', 8080)
    await site.start()
    
    print("Hardware Monitor started!")
    print("Web interface: http://localhost:8080")
    print("WebSocket: ws://localhost:8765")
    print("Press Ctrl+C to stop")
    
    # Start monitoring loop
    try:
        await asyncio.gather(
            websocket_server,
            monitor.monitoring_loop()
        )
    except KeyboardInterrupt:
        print("\nShutting down...")

if __name__ == "__main__":
    asyncio.run(main())