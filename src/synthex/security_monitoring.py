
"""
Security Monitoring and Alerting
"""
import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional
import asyncio
from collections import defaultdict
import os

class SecurityMonitor:
    """Security event monitoring and alerting"""
    
    def __init__(self):
        self.logger = logging.getLogger("security")
        self.event_counts = defaultdict(int)
        self.alert_thresholds = {
            "authentication_failure": 5,
            "authorization_failure": 10,
            "rate_limit_exceeded": 20,
            "suspicious_activity": 3,
            "sql_injection_attempt": 1,
            "xss_attempt": 1
        }
        self.alert_callbacks = []
        
    def log_security_event(self, event_type: str, details: Dict[str, Any], severity: str = "INFO"):
        """Log security event"""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "severity": severity,
            "details": details,
            "source_ip": details.get("source_ip", "unknown"),
            "user_id": details.get("user_id", "anonymous")
        }
        
        # Log event
        self.logger.log(
            getattr(logging, severity, logging.INFO),
            json.dumps(event)
        )
        
        # Count events
        self.event_counts[event_type] += 1
        
        # Check thresholds
        if event_type in self.alert_thresholds:
            if self.event_counts[event_type] >= self.alert_thresholds[event_type]:
                asyncio.create_task(self._trigger_alert(event_type, event))
                
    async def _trigger_alert(self, event_type: str, event: Dict[str, Any]):
        """Trigger security alert"""
        alert = {
            "alert_id": f"ALERT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "event_type": event_type,
            "threshold": self.alert_thresholds[event_type],
            "count": self.event_counts[event_type],
            "event": event,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Log alert
        self.logger.critical(f"SECURITY ALERT: {json.dumps(alert)}")
        
        # Call alert handlers
        for callback in self.alert_callbacks:
            try:
                await callback(alert)
            except Exception as e:
                self.logger.error(f"Alert callback failed: {e}")
                
        # Reset counter
        self.event_counts[event_type] = 0
        
    def register_alert_handler(self, callback):
        """Register alert handler"""
        self.alert_callbacks.append(callback)
        
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get security metrics"""
        return {
            "event_counts": dict(self.event_counts),
            "alerts_triggered": sum(1 for k, v in self.event_counts.items() 
                                  if k in self.alert_thresholds and v >= self.alert_thresholds[k]),
            "timestamp": datetime.utcnow().isoformat()
        }

# Global security monitor
security_monitor = SecurityMonitor()

# Configure security logging
security_handler = logging.FileHandler("security.log")
security_handler.setFormatter(
    logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
)
security_logger = logging.getLogger("security")
security_logger.addHandler(security_handler)
security_logger.setLevel(logging.INFO)
