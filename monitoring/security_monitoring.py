#!/usr/bin/env python3
"""
Real-time Security Monitoring and Alerting System
"""

import asyncio
import json
import logging
import time
import os
import hashlib
import socket
import psutil
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import defaultdict, deque
import subprocess
import re
import yaml
import sqlite3
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_id: str
    timestamp: str
    event_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    source: str
    description: str
    details: Dict[str, Any]
    status: str = "OPEN"  # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    remediation_steps: Optional[List[str]] = None

@dataclass
class SecurityMetric:
    """Security metric data structure"""
    metric_name: str
    value: float
    timestamp: str
    threshold: Optional[float] = None
    status: str = "NORMAL"  # NORMAL, WARNING, CRITICAL

@dataclass
class SecurityAlert:
    """Security alert data structure"""
    alert_id: str
    timestamp: str
    alert_type: str
    severity: str
    message: str
    affected_resources: List[str]
    recommended_actions: List[str]
    auto_remediate: bool = False

class SecurityMonitoringConfig:
    """Configuration for security monitoring"""
    
    def __init__(self, config_file: str = None):
        self.config = self._load_config(config_file)
        
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load monitoring configuration"""
        default_config = {
            "monitoring": {
                "enabled": True,
                "check_interval": 30,  # seconds
                "log_retention_days": 90,
                "max_events_per_hour": 1000
            },
            "intrusion_detection": {
                "enabled": True,
                "failed_login_threshold": 5,
                "failed_login_window": 300,  # 5 minutes
                "suspicious_process_patterns": [
                    r".*nc\s+-l.*",  # netcat listeners
                    r".*wget.*\.sh.*",  # suspicious downloads
                    r".*curl.*\|.*sh.*",  # piped shell execution
                    r".*python.*-c.*import.*"  # python one-liners
                ],
                "network_anomaly_detection": True
            },
            "file_integrity": {
                "enabled": True,
                "monitored_paths": [
                    "/etc/passwd",
                    "/etc/shadow",
                    "/etc/hosts",
                    "/etc/ssh/sshd_config",
                    "/usr/bin",
                    "/usr/sbin"
                ],
                "check_interval": 300  # 5 minutes
            },
            "log_analysis": {
                "enabled": True,
                "log_sources": [
                    "/var/log/auth.log",
                    "/var/log/syslog",
                    "/var/log/nginx/access.log",
                    "/var/log/nginx/error.log"
                ],
                "suspicious_patterns": [
                    r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)",
                    r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)",
                    r"Connection closed by .* \[preauth\]",
                    r"SQL injection attempt",
                    r"XSS attempt detected"
                ]
            },
            "network_monitoring": {
                "enabled": True,
                "monitor_connections": True,
                "suspicious_ports": [22, 23, 135, 139, 445, 1433, 3389],
                "max_connections_per_ip": 100,
                "connection_rate_limit": 50  # per minute
            },
            "threat_intelligence": {
                "enabled": True,
                "malicious_ip_feeds": [
                    "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/ips.txt"
                ],
                "update_interval": 3600  # 1 hour
            },
            "alerting": {
                "email_enabled": False,
                "slack_enabled": False,
                "syslog_enabled": True,
                "webhook_enabled": False,
                "alert_cooldown": 300,  # 5 minutes between similar alerts
                "severity_thresholds": {
                    "CRITICAL": 0,  # Always alert
                    "HIGH": 1,
                    "MEDIUM": 5,
                    "LOW": 10
                }
            },
            "auto_remediation": {
                "enabled": False,  # Disabled by default for safety
                "block_suspicious_ips": False,
                "kill_suspicious_processes": False,
                "quarantine_malicious_files": False
            }
        }
        
        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                file_config = yaml.safe_load(f)
                # Merge with defaults
                self._deep_update(default_config, file_config)
        
        return default_config
    
    def _deep_update(self, base_dict: Dict, update_dict: Dict):
        """Deep update dictionary"""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value

class SecurityEventDatabase:
    """SQLite database for storing security events"""
    
    def __init__(self, db_path: str = "security_events.db"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize the security events database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source TEXT NOT NULL,
                    description TEXT NOT NULL,
                    details TEXT,
                    status TEXT DEFAULT 'OPEN'
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_metrics (
                    metric_name TEXT,
                    value REAL,
                    timestamp TEXT,
                    threshold REAL,
                    status TEXT DEFAULT 'NORMAL'
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    affected_resources TEXT,
                    recommended_actions TEXT
                )
            """)
            
            # Create indexes for better performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON security_metrics(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp)")
    
    def store_event(self, event: SecurityEvent):
        """Store a security event"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO security_events 
                (event_id, timestamp, event_type, severity, source, description, details, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id, event.timestamp, event.event_type, 
                event.severity, event.source, event.description,
                json.dumps(event.details), event.status
            ))
    
    def store_metric(self, metric: SecurityMetric):
        """Store a security metric"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO security_metrics 
                (metric_name, value, timestamp, threshold, status)
                VALUES (?, ?, ?, ?, ?)
            """, (
                metric.metric_name, metric.value, metric.timestamp,
                metric.threshold, metric.status
            ))
    
    def store_alert(self, alert: SecurityAlert):
        """Store a security alert"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO security_alerts 
                (alert_id, timestamp, alert_type, severity, message, affected_resources, recommended_actions)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.alert_id, alert.timestamp, alert.alert_type,
                alert.severity, alert.message,
                json.dumps(alert.affected_resources),
                json.dumps(alert.recommended_actions)
            ))
    
    def get_recent_events(self, hours: int = 24) -> List[SecurityEvent]:
        """Get recent security events"""
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT * FROM security_events 
                WHERE timestamp > ? 
                ORDER BY timestamp DESC
            """, (since,))
            
            events = []
            for row in cursor.fetchall():
                events.append(SecurityEvent(
                    event_id=row[0],
                    timestamp=row[1],
                    event_type=row[2],
                    severity=row[3],
                    source=row[4],
                    description=row[5],
                    details=json.loads(row[6]) if row[6] else {},
                    status=row[7]
                ))
            
            return events

class IntrusionDetectionSystem:
    """Intrusion detection and prevention system"""
    
    def __init__(self, config: SecurityMonitoringConfig, event_db: SecurityEventDatabase):
        self.config = config.config["intrusion_detection"]
        self.event_db = event_db
        self.failed_logins = defaultdict(list)
        self.connection_tracker = defaultdict(list)
        self.process_baseline = set()
        self._establish_process_baseline()
    
    def _establish_process_baseline(self):
        """Establish baseline of running processes"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    process_info = proc.info
                    if process_info['cmdline']:
                        cmd_string = ' '.join(process_info['cmdline'])
                        self.process_baseline.add(cmd_string)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.error(f"Error establishing process baseline: {e}")
    
    async def monitor_failed_logins(self):
        """Monitor for failed login attempts"""
        if not self.config["enabled"]:
            return
        
        try:
            # Monitor auth.log for failed logins
            auth_log = "/var/log/auth.log"
            if os.path.exists(auth_log):
                with open(auth_log, 'r') as f:
                    # Read last 100 lines
                    lines = deque(f, maxlen=100)
                    
                    for line in lines:
                        if "Failed password" in line or "Invalid user" in line:
                            # Extract IP address
                            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                            if ip_match:
                                ip = ip_match.group(1)
                                current_time = time.time()
                                
                                # Clean old entries
                                cutoff_time = current_time - self.config["failed_login_window"]
                                self.failed_logins[ip] = [
                                    t for t in self.failed_logins[ip] if t > cutoff_time
                                ]
                                
                                # Add current failure
                                self.failed_logins[ip].append(current_time)
                                
                                # Check threshold
                                if len(self.failed_logins[ip]) >= self.config["failed_login_threshold"]:
                                    await self._generate_intrusion_event(
                                        "BRUTE_FORCE_ATTACK",
                                        "HIGH",
                                        f"Multiple failed login attempts from {ip}",
                                        {"ip_address": ip, "attempt_count": len(self.failed_logins[ip])}
                                    )
        
        except Exception as e:
            logger.error(f"Error monitoring failed logins: {e}")
    
    async def monitor_suspicious_processes(self):
        """Monitor for suspicious process execution"""
        if not self.config["enabled"]:
            return
        
        try:
            current_processes = set()
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                try:
                    process_info = proc.info
                    if process_info['cmdline']:
                        cmd_string = ' '.join(process_info['cmdline'])
                        current_processes.add(cmd_string)
                        
                        # Check if this is a new process (not in baseline)
                        if cmd_string not in self.process_baseline:
                            # Check against suspicious patterns
                            for pattern in self.config["suspicious_process_patterns"]:
                                if re.search(pattern, cmd_string, re.IGNORECASE):
                                    await self._generate_intrusion_event(
                                        "SUSPICIOUS_PROCESS",
                                        "MEDIUM",
                                        f"Suspicious process detected: {cmd_string}",
                                        {
                                            "pid": process_info['pid'],
                                            "command": cmd_string,
                                            "pattern_matched": pattern
                                        }
                                    )
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Update baseline with new legitimate processes
            # (This is a simplified approach - in production, you'd want more sophisticated learning)
            
        except Exception as e:
            logger.error(f"Error monitoring processes: {e}")
    
    async def monitor_network_connections(self):
        """Monitor network connections for anomalies"""
        if not self.config["enabled"]:
            return
        
        try:
            connections = psutil.net_connections(kind='inet')
            current_time = time.time()
            
            for conn in connections:
                if conn.raddr:  # Remote address exists
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    
                    # Track connections per IP
                    cutoff_time = current_time - 60  # 1 minute window
                    self.connection_tracker[remote_ip] = [
                        t for t in self.connection_tracker[remote_ip] if t > cutoff_time
                    ]
                    self.connection_tracker[remote_ip].append(current_time)
                    
                    # Check for suspicious ports
                    if remote_port in [22, 23, 135, 139, 445, 1433, 3389]:
                        await self._generate_intrusion_event(
                            "SUSPICIOUS_PORT_CONNECTION",
                            "MEDIUM",
                            f"Connection to suspicious port {remote_port} on {remote_ip}",
                            {"remote_ip": remote_ip, "remote_port": remote_port}
                        )
                    
                    # Check connection rate
                    if len(self.connection_tracker[remote_ip]) > 50:  # More than 50 connections per minute
                        await self._generate_intrusion_event(
                            "HIGH_CONNECTION_RATE",
                            "HIGH",
                            f"High connection rate from {remote_ip}",
                            {
                                "remote_ip": remote_ip,
                                "connection_count": len(self.connection_tracker[remote_ip])
                            }
                        )
        
        except Exception as e:
            logger.error(f"Error monitoring network connections: {e}")
    
    async def _generate_intrusion_event(self, event_type: str, severity: str, description: str, details: Dict[str, Any]):
        """Generate an intrusion detection event"""
        event = SecurityEvent(
            event_id=hashlib.md5(f"{event_type}_{description}_{time.time()}".encode()).hexdigest()[:16],
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            severity=severity,
            source="intrusion_detection",
            description=description,
            details=details
        )
        
        self.event_db.store_event(event)
        logger.warning(f"Intrusion event detected: {description}")

class FileIntegrityMonitor:
    """File integrity monitoring system"""
    
    def __init__(self, config: SecurityMonitoringConfig, event_db: SecurityEventDatabase):
        self.config = config.config["file_integrity"]
        self.event_db = event_db
        self.file_hashes = {}
        self._initialize_file_hashes()
    
    def _initialize_file_hashes(self):
        """Initialize baseline file hashes"""
        if not self.config["enabled"]:
            return
        
        for path in self.config["monitored_paths"]:
            if os.path.exists(path):
                if os.path.isfile(path):
                    self.file_hashes[path] = self._calculate_file_hash(path)
                elif os.path.isdir(path):
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            self.file_hashes[file_path] = self._calculate_file_hash(file_path)
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256()
                for chunk in iter(lambda: f.read(4096), b""):
                    file_hash.update(chunk)
                return file_hash.hexdigest()
        except Exception:
            return ""
    
    async def check_file_integrity(self):
        """Check file integrity against baseline"""
        if not self.config["enabled"]:
            return
        
        try:
            for file_path, baseline_hash in self.file_hashes.items():
                if os.path.exists(file_path):
                    current_hash = self._calculate_file_hash(file_path)
                    
                    if current_hash != baseline_hash and baseline_hash != "":
                        await self._generate_integrity_event(
                            file_path, baseline_hash, current_hash
                        )
                        # Update hash for future comparisons
                        self.file_hashes[file_path] = current_hash
                else:
                    # File was deleted
                    await self._generate_integrity_event(
                        file_path, baseline_hash, "FILE_DELETED"
                    )
        
        except Exception as e:
            logger.error(f"Error checking file integrity: {e}")
    
    async def _generate_integrity_event(self, file_path: str, old_hash: str, new_hash: str):
        """Generate a file integrity event"""
        event = SecurityEvent(
            event_id=hashlib.md5(f"file_integrity_{file_path}_{time.time()}".encode()).hexdigest()[:16],
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type="FILE_INTEGRITY_VIOLATION",
            severity="HIGH" if "/etc/" in file_path else "MEDIUM",
            source="file_integrity_monitor",
            description=f"File integrity violation detected: {file_path}",
            details={
                "file_path": file_path,
                "old_hash": old_hash,
                "new_hash": new_hash,
                "change_type": "DELETED" if new_hash == "FILE_DELETED" else "MODIFIED"
            }
        )
        
        self.event_db.store_event(event)
        logger.warning(f"File integrity violation: {file_path}")

class LogAnalyzer:
    """Log analysis and threat detection"""
    
    def __init__(self, config: SecurityMonitoringConfig, event_db: SecurityEventDatabase):
        self.config = config.config["log_analysis"]
        self.event_db = event_db
        self.processed_lines = {}
    
    async def analyze_logs(self):
        """Analyze log files for security threats"""
        if not self.config["enabled"]:
            return
        
        for log_file in self.config["log_sources"]:
            if os.path.exists(log_file):
                await self._analyze_log_file(log_file)
    
    async def _analyze_log_file(self, log_file: str):
        """Analyze a specific log file"""
        try:
            # Get file size to track position
            current_size = os.path.getsize(log_file)
            last_position = self.processed_lines.get(log_file, 0)
            
            if current_size < last_position:
                # File was rotated, start from beginning
                last_position = 0
            
            with open(log_file, 'r') as f:
                f.seek(last_position)
                new_lines = f.readlines()
                
                for line in new_lines:
                    await self._analyze_log_line(line, log_file)
                
                # Update processed position
                self.processed_lines[log_file] = f.tell()
        
        except Exception as e:
            logger.error(f"Error analyzing log file {log_file}: {e}")
    
    async def _analyze_log_line(self, line: str, source_file: str):
        """Analyze a single log line"""
        for pattern in self.config["suspicious_patterns"]:
            match = re.search(pattern, line)
            if match:
                await self._generate_log_event(line, pattern, match, source_file)
    
    async def _generate_log_event(self, log_line: str, pattern: str, match, source_file: str):
        """Generate a log analysis event"""
        event = SecurityEvent(
            event_id=hashlib.md5(f"log_analysis_{log_line}_{time.time()}".encode()).hexdigest()[:16],
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type="SUSPICIOUS_LOG_ENTRY",
            severity="MEDIUM",
            source="log_analyzer",
            description=f"Suspicious log entry detected in {source_file}",
            details={
                "log_line": log_line.strip(),
                "pattern_matched": pattern,
                "source_file": source_file,
                "matched_groups": match.groups() if match else []
            }
        )
        
        self.event_db.store_event(event)
        logger.info(f"Suspicious log entry detected in {source_file}")

class SecurityAlertManager:
    """Security alert management and notification system"""
    
    def __init__(self, config: SecurityMonitoringConfig, event_db: SecurityEventDatabase):
        self.config = config.config["alerting"]
        self.event_db = event_db
        self.alert_history = defaultdict(list)
    
    async def process_security_events(self):
        """Process recent security events and generate alerts"""
        if not self.config.get("enabled", True):
            return
        
        # Get recent events (last hour)
        recent_events = self.event_db.get_recent_events(hours=1)
        
        # Group events by type and severity
        event_groups = defaultdict(list)
        for event in recent_events:
            event_groups[f"{event.event_type}_{event.severity}"].append(event)
        
        # Generate alerts for significant event groups
        for group_key, events in event_groups.items():
            await self._evaluate_alert_criteria(group_key, events)
    
    async def _evaluate_alert_criteria(self, group_key: str, events: List[SecurityEvent]):
        """Evaluate if events meet alert criteria"""
        event_type, severity = group_key.rsplit('_', 1)
        event_count = len(events)
        
        # Get threshold for this severity
        threshold = self.config["severity_thresholds"].get(severity, 1)
        
        # Check if we should alert
        if event_count >= threshold:
            # Check cooldown period
            if self._is_in_cooldown(group_key):
                return
            
            # Generate alert
            alert = SecurityAlert(
                alert_id=hashlib.md5(f"{group_key}_{time.time()}".encode()).hexdigest()[:16],
                timestamp=datetime.now(timezone.utc).isoformat(),
                alert_type=event_type,
                severity=severity,
                message=f"{event_count} {event_type} events detected",
                affected_resources=[event.source for event in events],
                recommended_actions=self._get_recommended_actions(event_type, severity)
            )
            
            await self._send_alert(alert)
            self.event_db.store_alert(alert)
            
            # Update alert history for cooldown tracking
            self.alert_history[group_key].append(time.time())
    
    def _is_in_cooldown(self, group_key: str) -> bool:
        """Check if alert type is in cooldown period"""
        cooldown_period = self.config["alert_cooldown"]
        current_time = time.time()
        
        # Clean old alerts from history
        cutoff_time = current_time - cooldown_period
        self.alert_history[group_key] = [
            t for t in self.alert_history[group_key] if t > cutoff_time
        ]
        
        # Check if any recent alerts
        return len(self.alert_history[group_key]) > 0
    
    def _get_recommended_actions(self, event_type: str, severity: str) -> List[str]:
        """Get recommended actions for event type"""
        action_map = {
            "BRUTE_FORCE_ATTACK": [
                "Block the attacking IP address",
                "Review authentication logs",
                "Consider implementing fail2ban",
                "Verify password policies"
            ],
            "SUSPICIOUS_PROCESS": [
                "Investigate the process and its origin",
                "Check system integrity",
                "Review recent system changes",
                "Consider killing the process if malicious"
            ],
            "FILE_INTEGRITY_VIOLATION": [
                "Investigate the file changes",
                "Check system logs for unauthorized access",
                "Restore file from backup if compromised",
                "Review access controls"
            ],
            "SUSPICIOUS_LOG_ENTRY": [
                "Review full log context",
                "Investigate source of suspicious activity",
                "Check for additional indicators of compromise",
                "Consider blocking suspicious sources"
            ]
        }
        
        return action_map.get(event_type, ["Investigate the security event", "Review system logs"])
    
    async def _send_alert(self, alert: SecurityAlert):
        """Send alert through configured channels"""
        try:
            # Syslog notification
            if self.config.get("syslog_enabled", False):
                await self._send_syslog_alert(alert)
            
            # Email notification
            if self.config.get("email_enabled", False):
                await self._send_email_alert(alert)
            
            # Slack notification
            if self.config.get("slack_enabled", False):
                await self._send_slack_alert(alert)
            
            # Webhook notification
            if self.config.get("webhook_enabled", False):
                await self._send_webhook_alert(alert)
            
            logger.info(f"Security alert sent: {alert.message}")
        
        except Exception as e:
            logger.error(f"Error sending security alert: {e}")
    
    async def _send_syslog_alert(self, alert: SecurityAlert):
        """Send alert to syslog"""
        import syslog
        
        priority_map = {
            "CRITICAL": syslog.LOG_CRIT,
            "HIGH": syslog.LOG_ERR,
            "MEDIUM": syslog.LOG_WARNING,
            "LOW": syslog.LOG_INFO
        }
        
        priority = priority_map.get(alert.severity, syslog.LOG_INFO)
        message = f"SECURITY_ALERT: {alert.message} - {alert.alert_type}"
        
        syslog.openlog("security_monitor", syslog.LOG_PID, syslog.LOG_SECURITY)
        syslog.syslog(priority, message)
        syslog.closelog()
    
    async def _send_email_alert(self, alert: SecurityAlert):
        """Send alert via email"""
        # Implementation would depend on email configuration
        pass
    
    async def _send_slack_alert(self, alert: SecurityAlert):
        """Send alert to Slack"""
        # Implementation would depend on Slack webhook configuration
        pass
    
    async def _send_webhook_alert(self, alert: SecurityAlert):
        """Send alert via webhook"""
        # Implementation would depend on webhook configuration
        pass

class SecurityMonitoringSystem:
    """Main security monitoring system orchestrator"""
    
    def __init__(self, config_file: str = None):
        self.config = SecurityMonitoringConfig(config_file)
        self.event_db = SecurityEventDatabase()
        
        # Initialize monitoring components
        self.intrusion_detector = IntrusionDetectionSystem(self.config, self.event_db)
        self.file_monitor = FileIntegrityMonitor(self.config, self.event_db)
        self.log_analyzer = LogAnalyzer(self.config, self.event_db)
        self.alert_manager = SecurityAlertManager(self.config, self.event_db)
        
        self.monitoring_active = False
        self.monitoring_tasks = []
    
    async def start_monitoring(self):
        """Start the security monitoring system"""
        if self.monitoring_active:
            logger.warning("Security monitoring is already active")
            return
        
        self.monitoring_active = True
        logger.info("Starting security monitoring system...")
        
        # Start monitoring tasks
        monitoring_interval = self.config.config["monitoring"]["check_interval"]
        
        self.monitoring_tasks = [
            asyncio.create_task(self._run_periodic_task(
                self.intrusion_detector.monitor_failed_logins, monitoring_interval
            )),
            asyncio.create_task(self._run_periodic_task(
                self.intrusion_detector.monitor_suspicious_processes, monitoring_interval
            )),
            asyncio.create_task(self._run_periodic_task(
                self.intrusion_detector.monitor_network_connections, monitoring_interval
            )),
            asyncio.create_task(self._run_periodic_task(
                self.file_monitor.check_file_integrity, 
                self.config.config["file_integrity"]["check_interval"]
            )),
            asyncio.create_task(self._run_periodic_task(
                self.log_analyzer.analyze_logs, monitoring_interval
            )),
            asyncio.create_task(self._run_periodic_task(
                self.alert_manager.process_security_events, 60  # Check every minute
            ))
        ]
        
        logger.info("Security monitoring system started successfully")
    
    async def stop_monitoring(self):
        """Stop the security monitoring system"""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        logger.info("Stopping security monitoring system...")
        
        # Cancel all monitoring tasks
        for task in self.monitoring_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.monitoring_tasks, return_exceptions=True)
        
        logger.info("Security monitoring system stopped")
    
    async def _run_periodic_task(self, task_func: Callable, interval: int):
        """Run a task periodically"""
        while self.monitoring_active:
            try:
                await task_func()
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in periodic task {task_func.__name__}: {e}")
                await asyncio.sleep(interval)
    
    async def get_security_dashboard_data(self) -> Dict[str, Any]:
        """Get data for security dashboard"""
        # Get recent events (last 24 hours)
        recent_events = self.event_db.get_recent_events(hours=24)
        
        # Categorize events
        event_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        
        for event in recent_events:
            event_counts[event.event_type] += 1
            severity_counts[event.severity] += 1
        
        # Calculate security metrics
        security_score = max(0, 100 - (
            severity_counts["CRITICAL"] * 25 +
            severity_counts["HIGH"] * 10 +
            severity_counts["MEDIUM"] * 5 +
            severity_counts["LOW"] * 1
        ))
        
        return {
            "monitoring_status": "ACTIVE" if self.monitoring_active else "INACTIVE",
            "security_score": security_score,
            "recent_events": len(recent_events),
            "event_breakdown": dict(event_counts),
            "severity_breakdown": dict(severity_counts),
            "last_updated": datetime.now(timezone.utc).isoformat()
        }

# Command-line interface
async def main():
    """Main function for running security monitoring"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Security Monitoring System")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--dashboard", action="store_true", help="Show security dashboard")
    parser.add_argument("--daemon", action="store_true", help="Run as daemon")
    
    args = parser.parse_args()
    
    # Initialize monitoring system
    monitor = SecurityMonitoringSystem(args.config)
    
    if args.dashboard:
        # Show dashboard
        dashboard_data = await monitor.get_security_dashboard_data()
        print("Security Dashboard")
        print("=" * 50)
        print(f"Monitoring Status: {dashboard_data['monitoring_status']}")
        print(f"Security Score: {dashboard_data['security_score']}/100")
        print(f"Recent Events (24h): {dashboard_data['recent_events']}")
        print()
        print("Event Breakdown:")
        for event_type, count in dashboard_data['event_breakdown'].items():
            print(f"  {event_type}: {count}")
        print()
        print("Severity Breakdown:")
        for severity, count in dashboard_data['severity_breakdown'].items():
            print(f"  {severity}: {count}")
    
    elif args.daemon:
        # Run as daemon
        try:
            await monitor.start_monitoring()
            
            # Keep running until interrupted
            while True:
                await asyncio.sleep(60)
                dashboard_data = await monitor.get_security_dashboard_data()
                logger.info(f"Security monitoring active - Score: {dashboard_data['security_score']}/100")
        
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        finally:
            await monitor.stop_monitoring()
    
    else:
        # One-time check
        await monitor.start_monitoring()
        await asyncio.sleep(30)  # Run for 30 seconds
        await monitor.stop_monitoring()
        
        dashboard_data = await monitor.get_security_dashboard_data()
        print(f"Security check completed. Score: {dashboard_data['security_score']}/100")

if __name__ == "__main__":
    asyncio.run(main())